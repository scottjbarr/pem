package pem

import (
	"bytes"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

var (
	ErrDecode = errors.New("DH PARAMETERS block not found")
)

type Params struct {
	Prime     *big.Int
	Generator *big.Int
}

// Decode decodes the content PEM file that contains Diffie-Hellman parameters.
func Decode(b []byte) (*Params, error) {
	block, _ := pem.Decode(b)

	if block == nil || block.Type != "DH PARAMETERS" {
		return nil, ErrDecode
	}

	buf := bytes.NewBuffer(block.Bytes)

	buf.Next(3)

	// the size field will be either 1 of 2 bytes
	lenPrime := 0
	var n []byte

	if len(b) < 268 {
		// size is 1 byte
		n = make([]byte, 1, 1)
	} else {
		// size is represented by 2 bytes
		buf.Next(3)
		n = make([]byte, 2, 2)
	}

	// length of data
	if _, err := buf.Read(n); err != nil {
		return nil, err
	}

	if len(n) == 1 {
		// size is in one byte
		lenPrime = int(n[0])
	} else {
		// size is in 2 bytes
		i := binary.BigEndian.Uint16(n)
		lenPrime = int(i)
	}

	p := make([]byte, lenPrime, lenPrime)
	if _, err := buf.Read(p); err != nil {
		return nil, err
	}

	// the prime
	prime := new(big.Int)
	prime.SetBytes(p)

	// bytes before the generator
	buf.ReadByte() // 0x02
	buf.ReadByte() // 0x01

	// the generator
	g, _ := buf.ReadByte()
	generator := new(big.Int)
	generator.SetBytes([]byte{g})

	return NewParams(prime, generator), nil
}

func NewParams(prime, generator *big.Int) *Params {
	return &Params{
		Prime:     prime,
		Generator: generator,
	}
}

func printHex(label string, v interface{}) {
	fmt.Printf("%s = %v (%#x)\n", label, v, v)
}
