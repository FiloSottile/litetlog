//go:build mpt

package mpt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/bits"
)

type Label struct {
	bitLen uint32
	bytes  [32]byte
}

var RootLabel = Label{}

// EmptyNodeLabel is the label of the sibling of the only child of a root node.
var EmptyNodeLabel = Label{0, [32]byte{
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
}}

func NewLabel(bitLen uint32, bytes [32]byte) (Label, error) {
	if bitLen > 256 {
		return Label{}, errors.New("bit length exceeds maximum of 256 bits")
	}
	for i, b := range bytes {
		switch {
		case i == int(bitLen)/8 && bitLen%8 != 0:
			b = b << (bitLen % 8)
			fallthrough
		case i > int(bitLen)/8:
			if b != 0 {
				return Label{}, errors.New("non-zero bits in unused part of label")
			}
		}
	}
	return Label{bitLen, bytes}, nil
}

func (l Label) BitLen() uint32 {
	return l.bitLen
}

func (l Label) Bytes() []byte {
	b := make([]byte, 0, 4+32)
	b = binary.BigEndian.AppendUint32(b, l.bitLen)
	b = append(b, l.bytes[:]...)
	return b
}

func (l Label) Bit(i uint32) (byte, error) {
	if i >= l.bitLen {
		return 0, errors.New("bit index out of range")
	}
	byteIndex := i / 8
	bitIndex := i % 8
	return (l.bytes[byteIndex] >> (7 - bitIndex)) & 1, nil
}

// HasPrefix return whether prefix is equal to or a prefix of l.
func (l Label) HasPrefix(prefix Label) bool {
	if l.bitLen < prefix.bitLen {
		return false
	}
	bitLen := min(l.bitLen, prefix.bitLen)
	byteLen := bitLen / 8
	if !bytes.Equal(l.bytes[:byteLen], prefix.bytes[:byteLen]) {
		return false
	}
	if rem := bitLen % 8; rem != 0 {
		mask := byte(0xFF << (8 - rem))
		if l.bytes[byteLen]&mask != prefix.bytes[byteLen] {
			return false
		}
	}
	return true
}

func LongestCommonPrefix(l1, l2 Label) Label {
	var bitLen uint32
	var bytes [32]byte
	for i := range l1.bytes {
		n := bits.LeadingZeros8(l1.bytes[i] ^ l2.bytes[i])
		mask := byte(0xFF << (8 - n))
		bytes[i] = l1.bytes[i] & mask
		bitLen += uint32(n)
		if n < 8 {
			break
		}
	}
	bitLen = min(l1.bitLen, l2.bitLen, bitLen)
	return Label{bitLen, bytes}
}

type Side int

const (
	Left  Side = 0
	Right Side = 1

	NotAPrefix Side = -1
)

func (l Label) SideOf(prefix Label) Side {
	if !l.HasPrefix(prefix) || l.bitLen == prefix.bitLen {
		return NotAPrefix
	}
	b, err := l.Bit(prefix.bitLen)
	if err != nil {
		panic("mpt: internal error: bit index out of range")
	}
	return Side(b)
}
