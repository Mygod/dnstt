package noise

import (
	"bytes"
	"io"
	"testing"
)

func allMessages(buf []byte) ([][]byte, error) {
	var messages [][]byte
	r := bytes.NewReader(buf)
	for {
		msg, err := readMessage(r)
		if err != nil {
			return messages, err
		}
		messages = append(messages, msg)
	}
}

func messagesEqual(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

func TestReadMessage(t *testing.T) {
	for _, test := range []struct {
		input    string
		messages [][]byte
		err      error
	}{
		{"", [][]byte{}, io.EOF},
		{"\x00", [][]byte{}, io.ErrUnexpectedEOF},
		{"\x00\x00", [][]byte{{}}, io.EOF},
		{"\x00\x00\x00", [][]byte{{}}, io.ErrUnexpectedEOF},
		{"\x00\x01", [][]byte{}, io.ErrUnexpectedEOF},
		{"\x00\x05hello\x00\x05world", [][]byte{[]byte("hello"), []byte("world")}, io.EOF},
	} {
		packets, err := allMessages([]byte(test.input))
		if !messagesEqual(packets, test.messages) || err != test.err {
			t.Errorf("%x\nreturned %x %v\nexpected %x %v",
				test.input, packets, err, test.messages, test.err)
		}
	}
}

func TestMessageRoundTrip(t *testing.T) {
	for _, messages := range [][][]byte{
		{},
	} {
		var buf bytes.Buffer
		for _, msg := range messages {
			err := writeMessage(&buf, msg)
			if err != nil {
				panic(err)
			}
		}
		output, err := allMessages(buf.Bytes())
		if !messagesEqual(output, messages) || err != io.EOF {
			t.Errorf("%x roundtripped to %x %v",
				messages, output, err)
		}
	}
}

func TestReadKey(t *testing.T) {
	for _, test := range []struct {
		input  string
		output []byte
	}{
		{"", nil},
		{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde", nil},
		{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", []byte("\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef")},
		{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n", []byte("\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef")},
		{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0", nil},
		{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\nX", nil},
		{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\n", nil},
		{"\n0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", nil},
		{"X123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", nil},
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil},
	} {
		output, err := ReadKey(bytes.NewReader([]byte(test.input)))
		if test.output == nil {
			if err == nil {
				t.Errorf("%+q expected error", test.input)
			}
		} else {
			if err != nil {
				t.Errorf("%+q returned error %v", test.input, err)
			} else if !bytes.Equal(output, test.output) {
				t.Errorf("%+q got %x, expected %x", test.input, output, test.output)
			}
		}
	}
}
