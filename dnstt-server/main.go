package main

import (
	"bytes"
	"encoding/base32"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const (
	idleTimeout = 10 * time.Minute
	responseTTL = 60

	// We don't send UDP payloads larger than this, in an attempt to avoid
	// network-layer fragmentation. 40 bytes is the size of an IPv6 header
	// (though without any extension headers). 8 bytes is the size of a UDP
	// header.
	maxUDPPayload = 1500 - 40 - 8

	// We may have a variable amount of room in which to encode downstream
	// packets in each response, because we must echo the query's Question
	// section, which is of variable length. But we cannot give dynamic
	// packet size limits to KCP; the best we can do is set a global maximum
	// which no packet will exceed. We choose that maximum to keep the UDP
	// payload size under maxUDPPayload, even in the worst case of a
	// maximum-length name in the Question section. The precise limit is
	// 1153 = (maxUDPPayload - 294) * 255/256, where 294 is the size of a
	// DNS message containing a Question section with a name that is 255
	// bytes long, an Answer section with a single TXT RR whose name is a
	// compressed pointer to the name in the Question section and no data,
	// and an Additional section with an OPT RR for EDNS(0); and 255/256
	// reflects the overhead of encoding data into a TXT RR. We leave some
	// slack in case of IPv6 extension headers or non-Ethernet links.
	maxEncodedPayload = 1100
)

// A base32 encoding without padding.
var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// handleStream bidirectionally connects a client stream with the ORPort.
func handleStream(stream *smux.Stream, upstream *net.TCPAddr) error {
	conn, err := net.DialTCP("tcp", nil, upstream)
	if err != nil {
		return err
	}
	defer conn.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, conn)
		if err != nil {
			log.Printf("copy stream←upstream: %v\n", err)
		}
		stream.Close()
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := io.Copy(conn, stream)
		if err != nil {
			log.Printf("copy upstream←stream: %v\n", err)
		}
		conn.Close()
	}()
	wg.Wait()

	return nil
}

// acceptStreams layers an smux.Session on a KCP connection and awaits streams
// on it. It passes each stream to handleStream.
func acceptStreams(conn *kcp.UDPSession, upstream *net.TCPAddr) error {
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	sess, err := smux.Server(conn, smuxConfig)
	if err != nil {
		return err
	}

	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return err
		}
		go func() {
			defer stream.Close()
			err := handleStream(stream, upstream)
			if err != nil {
				log.Printf("handleStream: %v\n", err)
			}
		}()
	}
}

// acceptSessions listens for incoming KCP connections and passes them to
// acceptStreams.
func acceptSessions(ln *kcp.Listener, upstream *net.TCPAddr) error {
	for {
		conn, err := ln.AcceptKCP()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return err
		}
		// Permit coalescing the payloads of consecutive sends.
		conn.SetStreamMode(true)
		// Disable the dynamic congestion window (limit only by the
		// maximum of local and remote static windows).
		conn.SetNoDelay(
			0, // default nodelay
			0, // default interval
			0, // default resend
			1, // nc=1 => congestion window off
		)
		// Set the maximum transmission unit. 2 bytes accounts for a
		// packet length prefix.
		if rc := conn.SetMtu(maxEncodedPayload - 2); !rc {
			panic(rc)
		}
		go func() {
			defer conn.Close()
			err := acceptStreams(conn, upstream)
			if err != nil {
				log.Printf("acceptStreams: %v\n", err)
			}
		}()
	}
}

func nextPacket(r *bytes.Reader) ([]byte, error) {
	eof := func(err error) error {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}

	for {
		prefix, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if prefix >= 224 {
			paddingLen := prefix - 224
			_, err := io.CopyN(ioutil.Discard, r, int64(paddingLen))
			if err != nil {
				return nil, eof(err)
			}
			continue
		}
		p := make([]byte, int(prefix))
		_, err = io.ReadFull(r, p)
		return p, eof(err)
	}
}

func responseFor(query *dns.Message, domain dns.Name) (*dns.Message, turbotunnel.ClientID, []byte) {
	var clientID turbotunnel.ClientID

	resp := &dns.Message{
		ID:       query.ID,
		Flags:    0x8000, // QR = 1, RCODE = no error
		Question: query.Question,
	}

	if query.Flags&0x8000 != 0 {
		// QR != 0, this is not a query. Don't even send a response.
		return nil, clientID, nil
	}

	// Check for EDNS(0) support. Include our own OPT RR only if we receive
	// one from the requestor.
	// https://tools.ietf.org/html/rfc6891#section-6.1.1
	// "Lack of presence of an OPT record in a request MUST be taken as an
	// indication that the requestor does not implement any part of this
	// specification and that the responder MUST NOT include an OPT record
	// in its response."
	payloadSize := 0
	for _, rr := range query.Additional {
		if rr.Type != dns.RRTypeOPT {
			continue
		}
		if len(resp.Additional) != 0 {
			// https://tools.ietf.org/html/rfc6891#section-6.1.1
			// "If a query message with more than one OPT RR is
			// received, a FORMERR (RCODE=1) MUST be returned."
			resp.Flags |= dns.RcodeFormatError
			return resp, clientID, nil
		}
		resp.Additional = append(resp.Additional, dns.RR{
			Name:  dns.Name{},
			Type:  dns.RRTypeOPT,
			Class: 4096, // responder's UDP payload size
			TTL:   0,
			Data:  []byte{},
		})
		additional := &resp.Additional[0]

		version := (rr.TTL >> 16) & 0xff
		if version != 0 {
			// https://tools.ietf.org/html/rfc6891#section-6.1.1
			// "If a responder does not implement the VERSION level
			// of the request, then it MUST respond with
			// RCODE=BADVERS."
			resp.Flags |= dns.ExtendedRcodeBadVers & 0xf
			additional.TTL = (dns.ExtendedRcodeBadVers >> 4) << 24
		}

		payloadSize = int(rr.Class)
		if payloadSize < 512 {
			// https://tools.ietf.org/html/rfc6891#section-6.1.1
			// "Values lower than 512 MUST be treated as equal to
			// 512."
			payloadSize = 512
		}
	}
	// We will return RcodeFormatError if payloadSize is too small, but
	// first, check the name in order to set the AA bit properly.

	// There must be exactly one question.
	if len(query.Question) != 1 {
		resp.Flags |= dns.RcodeFormatError
		return resp, clientID, nil
	}
	question := query.Question[0]
	// Check the name to see if it ends in our chosen domain, and extract
	// all that comes before the domain if it does. If it does not, we will
	// return RcodeNameError below, but prefer to return RcodeFormatError
	// for payload size if that applies as well.
	prefix, ok := question.Name.TrimSuffix(domain)
	if ok {
		resp.Flags |= 0x0400 // AA = 1
	}

	// We require clients to support EDNS(0) with a minimum payload size;
	// otherwise we would have to set a small KCP MTU (only around 200
	// bytes). https://tools.ietf.org/html/rfc6891#section-7 "If there is a
	// problem with processing the OPT record itself, such as an option
	// value that is badly formatted or that includes out-of-range values, a
	// FORMERR MUST be returned."
	if payloadSize < maxUDPPayload {
		resp.Flags |= dns.RcodeFormatError
		return resp, clientID, nil
	}

	if resp.Flags|0x0400 == 0 { // AA
		// Not a name we are authoritative for.
		resp.Flags |= dns.RcodeNameError
		return resp, clientID, nil
	}

	if query.Flags&0x7800 != 0 {
		// We don't support OPCODE != QUERY.
		resp.Flags |= dns.RcodeNotImplemented
		return resp, clientID, nil
	}

	if question.Type != dns.RRTypeTXT {
		// We only support QTYPE == TXT.
		resp.Flags |= dns.RcodeNotImplemented
		return resp, clientID, nil
	}

	encoded := bytes.ToUpper(bytes.Join(prefix, nil))
	payload := make([]byte, base32Encoding.DecodedLen(len(encoded)))
	n, err := base32Encoding.Decode(payload, encoded)
	if err != nil {
		// Base32 error, make like the name doesn't exist.
		resp.Flags |= dns.RcodeNameError
		return resp, clientID, nil
	}
	payload = payload[:n]

	// Now extract the ClientID.
	n = copy(clientID[:], payload)
	if n < len(clientID) {
		// Payload is not long enough to contain a ClientID.
		resp.Flags |= dns.RcodeNameError
		return resp, clientID, nil
	}

	return resp, clientID, payload[len(clientID):]
}

// record represents a response set up with metadata appropriate for a response
// to a previously received query. recvLoop sends instances of this type to
// sendLoop via a channel. sendLoop may optionally fill in the response's Answer
// section before sending it.
type record struct {
	Resp     *dns.Message
	Addr     net.Addr
	ClientID turbotunnel.ClientID
}

func loop(dnsConn net.PacketConn, domain dns.Name, ttConn *turbotunnel.QueuePacketConn) error {
	ch := make(chan *record, 100)
	defer close(ch)

	go func() {
		err := sendLoop(dnsConn, ttConn, ch)
		if err != nil {
			log.Printf("sendLoop: %v", err)
		}
	}()

	return recvLoop(domain, dnsConn, ttConn, ch)
}

func recvLoop(domain dns.Name, dnsConn net.PacketConn, ttConn *turbotunnel.QueuePacketConn, ch chan<- *record) error {
	for {
		var buf [4096]byte
		n, addr, err := dnsConn.ReadFrom(buf[:])
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				log.Printf("ReadFrom temporary error: %v", err)
				continue
			}
			return err
		}

		// Got a UDP packet. Try to parse it as a DNS message.
		query, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
			log.Printf("%v: parsing DNS query: %v", addr, err)
			continue
		}

		resp, clientID, payload := responseFor(&query, domain)
		// If a response is called for, pass it to sendLoop via the channel.
		if resp != nil {
			select {
			case ch <- &record{resp, addr, clientID}:
			default:
			}
		}
		// Discard padding and pull out the packets contained in the payload.
		r := bytes.NewReader(payload)
		for {
			p, err := nextPacket(r)
			if err != nil {
				break
			}
			// Feed the incoming packet to KCP.
			ttConn.QueueIncoming(p, clientID)
		}
	}
}

func sendLoop(dnsConn net.PacketConn, ttConn *turbotunnel.QueuePacketConn, ch <-chan *record) error {
	var nextRec *record
	var nextP []byte
	for {
		rec := nextRec
		nextRec = nil

		if rec == nil {
			var ok bool
			rec, ok = <-ch
			if !ok {
				break
			}
		}

		if rec.Resp.Rcode() == dns.RcodeNoError && len(rec.Resp.Question) == 1 {
			// If it's a non-error response, we can fill the Answer
			// section with downstream packets.

			rec.Resp.Answer = []dns.RR{
				{
					Name:  rec.Resp.Question[0].Name,
					Type:  rec.Resp.Question[0].Type,
					Class: rec.Resp.Question[0].Class,
					TTL:   responseTTL,
					Data:  nil, // will be filled in below
				},
			}

			var payload bytes.Buffer

			limit := maxEncodedPayload
			if len(nextP) > 0 {
				// No length check on any packet left over from
				// the previous bundle -- if it's too large, we
				// allow it to be truncated and dropped.
				limit -= 2 + len(nextP)
				binary.Write(&payload, binary.BigEndian, uint16(len(nextP)))
				payload.Write(nextP)
			}
			nextP = nil

			timer := time.NewTimer(2 * time.Second)
		loop:
			for {
				select {
				case p := <-ttConn.OutgoingQueue(rec.ClientID):
					// We wait for the first packet in a
					// bundle only. The second and later
					// packets must be immediately available
					// or they will be omitted from this
					// send.
					timer.Reset(0)

					if int(uint16(len(p))) != len(p) {
						panic(len(p))
					}
					if 2+len(p) > limit {
						// Save this packet to send in
						// the next response.
						nextP = p
						break loop
					}
					limit -= 2 + len(p)
					binary.Write(&payload, binary.BigEndian, uint16(len(p)))
					payload.Write(p)
				default:
					select {
					case nextRec = <-ch:
						// If there's another response waiting
						// to be sent, wait no longer for a
						// payload for this one.
						break loop
					case <-timer.C:
						break loop
					}
				}
			}
			timer.Stop()

			rec.Resp.Answer[0].Data = dns.EncodeRDataTXT(payload.Bytes())
		}

		buf, err := rec.Resp.WireFormat()
		if err != nil {
			log.Printf("resp WireFormat: %v", err)
			continue
		}
		_, err = dnsConn.WriteTo(buf, rec.Addr)
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				log.Printf("WriteTo temporary error: %v", err)
				continue
			}
			return err
		}
	}
	return nil
}

type dummyAddr struct{}

func (addr dummyAddr) Network() string { return "dummy" }
func (addr dummyAddr) String() string  { return "dummy" }

func run(domain dns.Name, upstream net.Addr, udpAddr string) error {
	// Start up the virtual PacketConn for turbotunnel.
	ttConn := turbotunnel.NewQueuePacketConn(dummyAddr{}, idleTimeout*2)
	ln, err := kcp.ServeConn(nil, 0, 0, ttConn)
	if err != nil {
		return fmt.Errorf("opening KCP listener: %v", err)
	}
	defer ln.Close()
	go func() {
		err := acceptSessions(ln, upstream.(*net.TCPAddr))
		if err != nil {
			log.Printf("acceptSessions: %v\n", err)
		}
	}()

	var wg sync.WaitGroup

	if udpAddr != "" {
		dnsConn, err := net.ListenPacket("udp", udpAddr)
		if err != nil {
			return fmt.Errorf("opening UDP listener: %v", err)
		}
		wg.Add(1)
		go func() {
			defer dnsConn.Close()
			defer wg.Done()
			err := loop(dnsConn, domain, ttConn)
			if err != nil {
				log.Printf("error in UDP loop: %v\n", err)
			}
		}()
	}

	wg.Wait()
	return nil
}

func main() {
	var udpAddr string

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s -udp ADDR DOMAIN UPSTREAMADDR\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.StringVar(&udpAddr, "udp", "", "UDP address to listen on")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC)

	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(1)
	}
	domain, err := dns.ParseName(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid domain %+q: %v\n", flag.Arg(0), err)
		os.Exit(1)
	}
	upstream, err := net.ResolveTCPAddr("tcp", flag.Arg(1))
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot resolve %+q: %v\n", flag.Arg(1), err)
		os.Exit(1)
	}

	err = run(domain, upstream, udpAddr)
	if err != nil {
		log.Fatal(err)
	}
}
