package dns

import (
	"bytes"
)

type Name [][]byte

func ParseName(s []byte) (Name, error) {
	return bytes.Split(bytes.TrimSuffix(s, []byte(".")), []byte(".")), nil
}
