package recrypt

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"io"
	"math/big"

	crypt "github.com/ethereum/go-ethereum/crypto"
)

type capsule struct {
	E *ecdsa.PublicKey
	V *ecdsa.PublicKey
	S *big.Int
}

func encodeEncrypt(ct []byte, cap []byte, p *ecdsa.PublicKey) ([]byte, error) {
	buf := new(bytes.Buffer)

	// helper
	writeBytes := func(b []byte) error {
		length := uint32(len(b))
		if err := binary.Write(buf, binary.LittleEndian, length); err != nil {
			return err
		}
		if length > 0 {
			if _, err := buf.Write(b); err != nil {
				return err
			}
		}
		return nil
	}

	if err := writeBytes(ct); err != nil {
		return nil, err
	}
	if err := writeBytes(cap); err != nil {
		return nil, err
	}

	// serialize p (public key)
	if p != nil {
		pX, pY := p.X.Bytes(), p.Y.Bytes()
		binary.Write(buf, binary.LittleEndian, uint32(len(pX)))
		buf.Write(pX)
		binary.Write(buf, binary.LittleEndian, uint32(len(pY)))
		buf.Write(pY)
	}

	return buf.Bytes(), nil
}

func decodeEncrypt(data []byte) (ct []byte, cap []byte, p *ecdsa.PublicKey, err error) {
	buf := bytes.NewReader(data)
	readBytes := func() ([]byte, error) {
		var length uint32
		if err := binary.Read(buf, binary.LittleEndian, &length); err != nil {
			return nil, err
		}
		b := make([]byte, length)
		if length > 0 {
			if _, err := io.ReadFull(buf, b); err != nil {
				return nil, err
			}
		}
		return b, nil
	}

	ct, err = readBytes()
	if err != nil {
		return
	}
	cap, err = readBytes()
	if err != nil {
		return
	}

	p = new(ecdsa.PublicKey)
	p.Curve = crypt.S256()
	p.X, p.Y = readBig(buf), readBig(buf)

	return ct, cap, p, nil
}

func encodeRekey(r *big.Int, p *ecdsa.PublicKey) ([]byte, error) {
	buf := new(bytes.Buffer)

	// serialize r (big.Int)
	sBytes := r.Bytes()
	binary.Write(buf, binary.LittleEndian, uint32(len(sBytes)))
	buf.Write(sBytes)

	// serialize p (public key)
	pX, pY := p.X.Bytes(), p.Y.Bytes()
	binary.Write(buf, binary.LittleEndian, uint32(len(pX)))
	buf.Write(pX)
	binary.Write(buf, binary.LittleEndian, uint32(len(pY)))
	buf.Write(pY)

	return buf.Bytes(), nil
}

func decodeRekey(data []byte) (*big.Int, *ecdsa.PublicKey, error) {
	rData := bytes.NewReader(data)

	var r = readBig(rData)

	p := new(ecdsa.PublicKey)
	p.Curve = crypt.S256()
	p.X, p.Y = readBig(rData), readBig(rData)

	return r, p, nil
}

func encodeCapsule(e, v *ecdsa.PublicKey, s *big.Int) ([]byte, error) {
	buf := new(bytes.Buffer)

	// serialize E (public key)
	ecX, ecY := e.X.Bytes(), e.Y.Bytes()
	binary.Write(buf, binary.LittleEndian, uint32(len(ecX)))
	buf.Write(ecX)
	binary.Write(buf, binary.LittleEndian, uint32(len(ecY)))
	buf.Write(ecY)

	// serialize V (public key)
	vX, vY := v.X.Bytes(), v.Y.Bytes()
	binary.Write(buf, binary.LittleEndian, uint32(len(vX)))
	buf.Write(vX)
	binary.Write(buf, binary.LittleEndian, uint32(len(vY)))
	buf.Write(vY)

	// serialize S (big.Int)
	sBytes := s.Bytes()
	binary.Write(buf, binary.LittleEndian, uint32(len(sBytes)))
	buf.Write(sBytes)

	return buf.Bytes(), nil
}

func decodeCapsule(data []byte) (*capsule, error) {
	r := bytes.NewReader(data)
	c := new(capsule)

	c.E = new(ecdsa.PublicKey)
	c.E.Curve = crypt.S256()
	c.V = new(ecdsa.PublicKey)
	c.V.Curve = crypt.S256()

	c.E.X, c.E.Y = readBig(r), readBig(r)
	c.V.X, c.V.Y = readBig(r), readBig(r)
	c.S = readBig(r)

	return c, nil
}

func readBig(r *bytes.Reader) *big.Int {
	var l uint32

	binary.Read(r, binary.LittleEndian, &l)
	b := make([]byte, l)
	r.Read(b)

	return new(big.Int).SetBytes(b)
}
