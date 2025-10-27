package utils

import (
	"crypto/ecdsa"
	"encoding/hex"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/kaleido-io/vault-plugin-secrets-ethsign/pre/curve"
)

// Generate Private and Public key-pair
func GenerateKeys() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// convert string to private key
func PrivateKeyStrToKey(privateKeyStr string) (*ecdsa.PrivateKey, error) {
	priKeyAsBytes, err := hex.DecodeString(privateKeyStr)
	if err != nil {
		return nil, err
	}
	d := new(big.Int).SetBytes(priKeyAsBytes)
	// compute public key
	x, y := crypto.S256().ScalarBaseMult(priKeyAsBytes)
	pubKey := ecdsa.PublicKey{
		curve.CURVE, x, y,
	}
	key := &ecdsa.PrivateKey{
		D:         d,
		PublicKey: pubKey,
	}
	return key, nil
}

// convert public key string to key
func PublicKeyStrToKey(pubKey string) (*ecdsa.PublicKey, error) {
	pubKeyAsBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		return nil, err
	}
	return crypto.UnmarshalPubkey(pubKeyAsBytes)
}

func PrivateKeyToStr(privateKey *ecdsa.PrivateKey) string {
	return hex.EncodeToString(privateKey.D.Bytes())
}

func PublicKeyToStr(publicKey *ecdsa.PublicKey) string {
	return hex.EncodeToString(crypto.FromECDSAPub(publicKey))
}
