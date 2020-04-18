package noise

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/flynn/noise"
)

func readMessage(r io.Reader) ([]byte, error) {
	var length uint16
	err := binary.Read(r, binary.BigEndian, &length)
	if err != nil {
		return nil, err
	}
	msg := make([]byte, int(length))
	_, err = io.ReadFull(r, msg)
	if err != nil {
		return nil, nil
	}
	return msg, nil
}

func writeMessage(w io.Writer, msg []byte) error {
	length := uint16(len(msg))
	if int(length) != len(msg) {
		panic(len(msg))
	}
	err := binary.Write(w, binary.BigEndian, length)
	if err != nil {
		return err
	}
	_, err = w.Write(msg)
	return err
}

type ReadWriter struct {
	rw         io.ReadWriteCloser
	recvPipe   *io.PipeReader
	sendCipher *noise.CipherState
}

func newReadWriter(rw io.ReadWriteCloser, recvCipher, sendCipher *noise.CipherState) *ReadWriter {
	pr, pw := io.Pipe()
	go func() (err error) {
		defer func() {
			pw.CloseWithError(err)
		}()
		for {
			msg, err := readMessage(rw)
			if err != nil {
				return err
			}
			p, err := recvCipher.Decrypt(nil, nil, msg)
			if err != nil {
				return err
			}
			_, err = pw.Write(p)
			if err != nil {
				return err
			}
		}
	}()
	return &ReadWriter{
		rw:         rw,
		sendCipher: sendCipher,
		recvPipe:   pr,
	}
}

func (rw *ReadWriter) Read(p []byte) (int, error) {
	return rw.recvPipe.Read(p)
}

func (rw *ReadWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > 4096 {
			n = 4096
		}
		err := writeMessage(rw.rw, rw.sendCipher.Encrypt(nil, nil, p[:n]))
		if err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (rw *ReadWriter) Close() error {
	return rw.rw.Close()
}

var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

func newConfig(initiator bool) noise.Config {
	return noise.Config{
		CipherSuite: cipherSuite,
		Pattern:     noise.HandshakeNK,
		Initiator:   initiator,
		Prologue:    []byte("dnstt 2020-04-13"),
	}
}

func NewClient(rw io.ReadWriteCloser, serverPubkey []byte) (*ReadWriter, error) {
	config := newConfig(true)
	config.PeerStatic = serverPubkey
	handshakeState, err := noise.NewHandshakeState(config)
	if err != nil {
		return nil, err
	}

	// -> e, es
	msg, _, _, err := handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return nil, err
	}
	err = writeMessage(rw, msg)
	if err != nil {
		return nil, err
	}

	// <- e, es
	msg, err = readMessage(rw)
	if err != nil {
		return nil, err
	}
	payload, sendCipher, recvCipher, err := handshakeState.ReadMessage(nil, msg)
	if err != nil {
		return nil, err
	}
	if len(payload) != 0 {
		return nil, errors.New("unexpected server payload")
	}

	return newReadWriter(rw, recvCipher, sendCipher), nil
}

func NewServer(rw io.ReadWriteCloser, serverPrivkey, serverPubkey []byte) (*ReadWriter, error) {
	config := newConfig(false)
	config.StaticKeypair = noise.DHKey{Private: serverPrivkey, Public: serverPubkey}
	handshakeState, err := noise.NewHandshakeState(config)
	if err != nil {
		return nil, err
	}

	// -> e, es
	msg, err := readMessage(rw)
	if err != nil {
		return nil, err
	}
	payload, _, _, err := handshakeState.ReadMessage(nil, msg)
	if err != nil {
		return nil, err
	}
	if len(payload) != 0 {
		return nil, errors.New("unexpected server payload")
	}

	// <- e, es
	msg, recvCipher, sendCipher, err := handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return nil, err
	}
	err = writeMessage(rw, msg)
	if err != nil {
		return nil, err
	}

	return newReadWriter(rw, recvCipher, sendCipher), nil
}

func GenerateKeypair() (privkey, pubkey []byte, err error) {
	pair, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// pair.Public is already filled in; assert here that PubkeyFromPrivkey
	// agrees with it.
	derivedPubkey := PubkeyFromPrivkey(pair.Private)
	if !bytes.Equal(derivedPubkey, pair.Public) {
		panic(fmt.Sprintf("expected pubkey %x, got %x", derivedPubkey, pair.Public))
	}

	return pair.Private, pair.Public, nil
}

func PubkeyFromPrivkey(privkey []byte) []byte {
	pair, err := noise.DH25519.GenerateKeypair(bytes.NewReader(privkey))
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(pair.Private, privkey) {
		panic("privkey was not as expected")
	}
	return pair.Public
}
