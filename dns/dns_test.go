package dns

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func namesEqual(a, b Name) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

func anyLabelContainsDot(labels [][]byte) bool {
	for _, label := range labels {
		if bytes.Contains(label, []byte(".")) {
			return true
		}
	}
	return false
}

func TestName(t *testing.T) {
	for _, test := range []struct {
		labels [][]byte
		err    error
		s      string
	}{
		{[][]byte{}, nil, "."},
		{[][]byte{[]byte("test")}, nil, "test"},
		{[][]byte{[]byte("a"), []byte("b"), []byte("c")}, nil, "a.b.c"},

		{[][]byte{[]byte{}}, ErrZeroLengthLabel, ""},
		{[][]byte{[]byte("a"), []byte{}, []byte("c")}, ErrZeroLengthLabel, ""},

		// 63 octets.
		{[][]byte{[]byte("0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDE")}, nil,
			"0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDE"},
		// 64 octets.
		{[][]byte{[]byte("0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF")}, ErrLabelTooLong, ""},

		// 64+64+64+61 octets.
		{[][]byte{
			[]byte("0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDE"),
			[]byte("0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDE"),
			[]byte("0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDE"),
			[]byte("0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABC"),
		}, nil,
			"0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDE.0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDE.0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDE.0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABC"},
		// 64+64+64+62 octets.
		{[][]byte{
			[]byte("0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDE"),
			[]byte("0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDE"),
			[]byte("0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDE"),
			[]byte("0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCD"),
		}, ErrNameTooLong, ""},
		// 127 one-octet labels.
		{[][]byte{
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'a'}, {'b'}, {'c'}, {'d'}, {'e'}, {'f'},
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'A'}, {'B'}, {'C'}, {'D'}, {'E'}, {'F'},
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'a'}, {'b'}, {'c'}, {'d'}, {'e'}, {'f'},
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'A'}, {'B'}, {'C'}, {'D'}, {'E'}, {'F'},
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'a'}, {'b'}, {'c'}, {'d'}, {'e'}, {'f'},
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'A'}, {'B'}, {'C'}, {'D'}, {'E'}, {'F'},
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'a'}, {'b'}, {'c'}, {'d'}, {'e'}, {'f'},
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'A'}, {'B'}, {'C'}, {'D'}, {'E'},
		}, nil,
			"0.1.2.3.4.5.6.7.8.9.a.b.c.d.e.f.0.1.2.3.4.5.6.7.8.9.A.B.C.D.E.F.0.1.2.3.4.5.6.7.8.9.a.b.c.d.e.f.0.1.2.3.4.5.6.7.8.9.A.B.C.D.E.F.0.1.2.3.4.5.6.7.8.9.a.b.c.d.e.f.0.1.2.3.4.5.6.7.8.9.A.B.C.D.E.F.0.1.2.3.4.5.6.7.8.9.a.b.c.d.e.f.0.1.2.3.4.5.6.7.8.9.A.B.C.D.E"},
		// 128 one-octet labels.
		{[][]byte{
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'a'}, {'b'}, {'c'}, {'d'}, {'e'}, {'f'},
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'A'}, {'B'}, {'C'}, {'D'}, {'E'}, {'F'},
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'a'}, {'b'}, {'c'}, {'d'}, {'e'}, {'f'},
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'A'}, {'B'}, {'C'}, {'D'}, {'E'}, {'F'},
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'a'}, {'b'}, {'c'}, {'d'}, {'e'}, {'f'},
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'A'}, {'B'}, {'C'}, {'D'}, {'E'}, {'F'},
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'a'}, {'b'}, {'c'}, {'d'}, {'e'}, {'f'},
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'A'}, {'B'}, {'C'}, {'D'}, {'E'}, {'F'},
		}, ErrNameTooLong, ""},

		// Labels may contain any octets, though ones containing dots
		// cannot be losslessly roundtripped through a string.
		{[][]byte{[]byte("\x00"), []byte("a.b")}, nil, "\x00.a.b"},
	} {
		// Test that NewName returns proper error codes, and otherwise
		// returns an equal slice of labels.
		name, err := NewName(test.labels)
		if err != test.err || (err == nil && !namesEqual(name, test.labels)) {
			t.Errorf("%+q returned (%+q, %v), expected (%+q, %v)",
				test.labels, name, err, test.labels, test.err)
			continue
		}
		if test.err != nil {
			continue
		}

		// Test that the string version of the name comes out as
		// expected.
		s := name.String()
		if s != test.s {
			t.Errorf("%+q became string %+q, expected %+q", test.labels, s, test.s)
			continue
		}

		// Test that parsing from a string back to a Name results in the
		// original slice of labels.
		if !anyLabelContainsDot(test.labels) {
			name, err := ParseName(s)
			if err != nil || !namesEqual(name, test.labels) {
				t.Errorf("%+q parsing %+q returned (%+q, %v), expected (%+q, %v)",
					test.labels, s, name, err, test.labels, nil)
				continue
			}
			// A trailing dot should be ignored.
			if !strings.HasSuffix(s, ".") {
				dotName, dotErr := ParseName(s + ".")
				if dotErr != err || !namesEqual(dotName, name) {
					t.Errorf("%+q parsing %+q returned (%+q, %v), expected (%+q, %v)",
						test.labels, s+".", dotName, dotErr, name, err)
					continue
				}
			}
		}
	}
}

func TestParseName(t *testing.T) {
	for _, test := range []struct {
		s    string
		name Name
		err  error
	}{
		// This case can't be tested by TestName above because String
		// will never produce "" (it produces "." instead).
		{"", [][]byte{}, nil},
	} {
		name, err := ParseName(test.s)
		if err != test.err || (err == nil && !namesEqual(name, test.name)) {
			t.Errorf("%+q returned (%+q, %v), expected (%+q, %v)",
				test.s, name, err, test.name, test.err)
			continue
		}
	}
}

func TestReadName(t *testing.T) {
	// Good tests.
	for _, test := range []struct {
		start int64
		end   int64
		input string
		s     string
	}{
		// Empty name.
		{0, 1, "\x00abcd", "."},
		// No pointers.
		{12, 25, "AAAABBBBCCCC\x07example\x03com\x00", "example.com"},
		// Backward pointer.
		{25, 31, "AAAABBBBCCCC\x07example\x03com\x00\x03sub\xc0\x0c", "sub.example.com"},
		// Forward pointer.
		{0, 4, "\x01a\xc0\x04\x03bcd\x00", "a.bcd"},
		// Two backwards pointers.
		{31, 38, "AAAABBBBCCCC\x07example\x03com\x00\x03sub\xc0\x0c\x04sub2\xc0\x19", "sub2.sub.example.com"},
		// Forward then backward pointer.
		{25, 31, "AAAABBBBCCCC\x07example\x03com\x00\x03sub\xc0\x1f\x04sub2\xc0\x0c", "sub.sub2.example.com"},
		// Overlapping codons.
		{0, 4, "\x01a\xc0\x03bcd\x00", "a.bcd"},
		// Pointer to empty label.
		{0, 10, "\x07example\xc0\x0a\x00", "example"},
		{1, 11, "\x00\x07example\xc0\x00", "example"},
		// Pointer to pointer to empty label.
		{0, 10, "\x07example\xc0\x0a\xc0\x0c\x00", "example"},
		{1, 11, "\x00\x07example\xc0\x0c\xc0\x00", "example"},
	} {
		r := bytes.NewReader([]byte(test.input))
		_, err := r.Seek(test.start, io.SeekStart)
		if err != nil {
			panic(err)
		}
		name, err := readName(r)
		if err != nil {
			t.Errorf("%+q returned error %s", test.input, err)
			continue
		}
		s := name.String()
		if s != test.s {
			t.Errorf("%+q returned %+q, expected %+q", test.input, s, test.s)
			continue
		}
		cur, _ := r.Seek(0, io.SeekCurrent)
		if cur != test.end {
			t.Errorf("%+q left offset %d, expected %d", test.input, cur, test.end)
			continue
		}
	}

	// Bad tests.
	for _, test := range []struct {
		start int64
		input string
		err   error
	}{
		{0, "", io.ErrUnexpectedEOF},
		// Reserved label type.
		{0, "\x80example", ErrReservedLabelType},
		// Reserved label type.
		{0, "\x40example", ErrReservedLabelType},
		// No Terminating empty label.
		{0, "\x07example\x03com", io.ErrUnexpectedEOF},
		// Pointer past end of buffer.
		{0, "\x07example\xc0\xff", io.ErrUnexpectedEOF},
		// Pointer to self.
		{0, "\x07example\x03com\xc0\x0c", ErrTooManyPointers},
		// Pointer to self with intermediate label.
		{0, "\x07example\x03com\xc0\x08", ErrTooManyPointers},
		// Two pointers that point to each other.
		{0, "\xc0\x02\xc0\x00", ErrTooManyPointers},
		// Two pointers that point to each other, with intermediate labels.
		{0, "\x01a\xc0\x04\x01b\xc0\x00", ErrTooManyPointers},
		// EOF while reading label.
		{0, "\x0aexample", io.ErrUnexpectedEOF},
		// EOF before second byte of pointer.
		{0, "\x07example\xc0", io.ErrUnexpectedEOF},
	} {
		r := bytes.NewReader([]byte(test.input))
		_, err := r.Seek(test.start, io.SeekStart)
		if err != nil {
			panic(err)
		}
		name, err := readName(r)
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		if err != test.err {
			t.Errorf("%+q returned (%+q, %v), expected %v", test.input, name, err, test.err)
			continue
		}
	}
}

func mustParseName(s string) Name {
	name, err := ParseName(s)
	if err != nil {
		panic(err)
	}
	return name
}

func questionsEqual(a, b *Question) bool {
	if !namesEqual(a.Name, b.Name) {
		return false
	}
	if a.Type != b.Type || a.Class != b.Class {
		return false
	}
	return true
}

func rrsEqual(a, b *RR) bool {
	if !namesEqual(a.Name, b.Name) {
		return false
	}
	if a.Type != b.Type || a.Class != b.Class || a.TTL != b.TTL {
		return false
	}
	if !bytes.Equal(a.Data, b.Data) {
		return false
	}
	return true
}

func messagesEqual(a, b *Message) bool {
	if a.ID != b.ID || a.Flags != b.Flags {
		return false
	}
	if len(a.Question) != len(b.Question) {
		return false
	}
	for i := 0; i < len(a.Question); i++ {
		if !questionsEqual(&a.Question[i], &b.Question[i]) {
			return false
		}
	}
	for _, rec := range []struct{ rrA, rrB []RR }{
		{a.Answer, b.Answer},
		{a.Authority, b.Authority},
		{a.Additional, b.Additional},
	} {
		if len(rec.rrA) != len(rec.rrB) {
			return false
		}
		for i := 0; i < len(rec.rrA); i++ {
			if !rrsEqual(&rec.rrA[i], &rec.rrB[i]) {
				return false
			}
		}
	}
	return true
}

func TestMessageFromWireFormat(t *testing.T) {
	for _, test := range []struct {
		buf      string
		expected Message
		err      error
	}{
		{
			"\x12\x34",
			Message{},
			io.ErrUnexpectedEOF,
		},
		{
			"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01",
			Message{
				ID:    0x1234,
				Flags: 0x0100,
				Question: []Question{
					{
						Name:  mustParseName("www.example.com"),
						Type:  1,
						Class: 1,
					},
				},
				Answer:     []RR{},
				Authority:  []RR{},
				Additional: []RR{},
			},
			nil,
		},
		{
			"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01X",
			Message{},
			ErrTrailingBytes,
		},
		{
			"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01\x03www\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x80\x00\x04\xc0\x00\x02\x01",
			Message{
				ID:    0x1234,
				Flags: 0x8180,
				Question: []Question{
					{
						Name:  mustParseName("www.example.com"),
						Type:  1,
						Class: 1,
					},
				},
				Answer: []RR{
					{
						Name:  mustParseName("www.example.com"),
						Type:  1,
						Class: 1,
						TTL:   128,
						Data:  []byte{192, 0, 2, 1},
					},
				},
				Authority:  []RR{},
				Additional: []RR{},
			},
			nil,
		},
	} {
		message, err := MessageFromWireFormat([]byte(test.buf))
		if err != test.err || (err == nil && !messagesEqual(&message, &test.expected)) {
			t.Errorf("%+q\nreturned (%+v, %v)\nexpected (%+v, %v)",
				test.buf, message, err, test.expected, test.err)
			continue
		}
	}
}
