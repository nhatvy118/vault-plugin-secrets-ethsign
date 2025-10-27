package recrypt

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"

	"github.com/kaleido-io/vault-plugin-secrets-ethsign/pre/curve"
	"github.com/kaleido-io/vault-plugin-secrets-ethsign/pre/utils"
)

// Encrypt the message
// AES GCM + Proxy Re-Encryption
func Encrypt(data []byte, pubKey *ecdsa.PublicKey) ([]byte, []byte, error) {
	capsule, keyBytes, err := encryptKeyGen(pubKey)
	if err != nil {
		return nil, nil, err
	}

	// use aes gcm algorithm to encrypt
	// mark keyBytes[:12] as nonce
	key := hex.EncodeToString(keyBytes)
	cipherText, err := GCMEncrypt(data, key[:32], keyBytes[:12], nil)
	if err != nil {
		return nil, nil, err
	}

	capsuleAsBytes, err := encodeCapsule(capsule.E, capsule.V, capsule.S)
	if err != nil {
		return nil, nil, err
	}

	return capsuleAsBytes, cipherText, nil
}

func ReEncrypt(cap []byte, rekeyBytes []byte) ([]byte, error) {
	r, pubX, err := decodeRekey(rekeyBytes)
	if err != nil {
		return nil, err
	}

	decodeCap, err := decodeCapsule(cap)
	if err != nil {
		fmt.Println("decode error:", err)

		return nil, err
	}

	reCap, err := reEncryption(r, decodeCap)
	if err != nil {
		fmt.Println("re encryption error:", err)

		return nil, err
	}

	reCapsuleAsBytes, err := encodeCapsule(reCap.E, reCap.V, reCap.S)
	if err != nil {
		fmt.Println("encode error:", err)

		return nil, err
	}

	return utils.ConcatBytes(reCapsuleAsBytes, curve.PointToBytes(pubX)), nil
}

func CreateRekey(priKey *ecdsa.PrivateKey, pkey *ecdsa.PublicKey) ([]byte, error) {
	r, p, err := rekeyGenerate(priKey, pkey)
	if err != nil {
		fmt.Println(err)
	}

	return encodeRekey(r, p)
}

func Decrypt(cipherText []byte, reCap []byte, priKey *ecdsa.PrivateKey) (decryptData []byte, err error) {
	if len(reCap) != 245 {
		return nil, fmt.Errorf("reCap length is not 245")
	}
	// convert to cap, pubX
	cap := reCap[:180]
	pubXBytes := reCap[180:]

	pubX, err := curve.BytesToPublicKey(pubXBytes)
	if err != nil {
		return nil, err
	}

	log.Println("cap:", len(cap))
	log.Println("pubX:", len(pubXBytes))

	decodeCapsule, err := decodeCapsule(cap)
	if err != nil {
		return nil, err
	}

	decryptData, err = decrypt(priKey, decodeCapsule, pubX, cipherText)
	if err != nil {
		return nil, err
	}

	return decryptData, nil
}

// Server executes Re-Encryption method
func reEncryption(rk *big.Int, cap *capsule) (*capsule, error) {
	// check g^s == V * E^{H2(E || V)}
	x1, y1 := curve.CURVE.ScalarBaseMult(cap.S.Bytes())
	tempX, tempY := curve.CURVE.ScalarMult(cap.E.X, cap.E.Y,
		utils.HashToCurve(
			utils.ConcatBytes(
				curve.PointToBytes(cap.E),
				curve.PointToBytes(cap.V))).Bytes())
	x2, y2 := curve.CURVE.Add(cap.V.X, cap.V.Y, tempX, tempY)

	// if check failed return error
	if x1.Cmp(x2) != 0 || y1.Cmp(y2) != 0 {
		return nil, fmt.Errorf("%s", "Capsule not match")
	}

	// E' = E^{rk}, V' = V^{rk}
	newCapsule := &capsule{
		E: curve.PointScalarMul(cap.E, rk),
		V: curve.PointScalarMul(cap.V, rk),
		S: cap.S,
	}

	return newCapsule, nil
}

func encryptKeyGen(pubKey *ecdsa.PublicKey) (cap *capsule, keyBytes []byte, err error) {
	s := new(big.Int)
	// generate E,V key-pairs
	priE, pubE, err := utils.GenerateKeys()
	priV, pubV, err := utils.GenerateKeys()
	if err != nil {
		return nil, nil, err
	}
	// get H2(E || V)
	h := utils.HashToCurve(
		utils.ConcatBytes(
			curve.PointToBytes(pubE),
			curve.PointToBytes(pubV)))
	// get s = v + e * H2(E || V)
	s = curve.BigIntAdd(priV.D, curve.BigIntMul(priE.D, h))
	// get (pk_A)^{e+v}
	point := curve.PointScalarMul(pubKey, curve.BigIntAdd(priE.D, priV.D))
	// generate aes key
	keyBytes, err = utils.Sha3Hash(curve.PointToBytes(point))
	if err != nil {
		return nil, nil, err
	}

	cap = &capsule{
		E: pubE,
		V: pubV,
		S: s,
	}

	return cap, keyBytes, nil
}

// generate re-encryption key and sends it to Server
// rk = sk_A * d^{-1}
func rekeyGenerate(aPriKey *ecdsa.PrivateKey, bPubKey *ecdsa.PublicKey) (*big.Int, *ecdsa.PublicKey, error) {
	// generate x,X key-pair
	priX, pubX, err := utils.GenerateKeys()
	if err != nil {
		return nil, nil, err
	}
	// get d = H3(X_A || pk_B || pk_B^{x_A})
	point := curve.PointScalarMul(bPubKey, priX.D)
	d := utils.HashToCurve(
		utils.ConcatBytes(
			utils.ConcatBytes(
				curve.PointToBytes(pubX),
				curve.PointToBytes(bPubKey)),
			curve.PointToBytes(point)))
	// rk = sk_A * d^{-1}
	rk := curve.BigIntMul(aPriKey.D, curve.GetInvert(d))
	rk.Mod(rk, curve.N)

	return rk, pubX, nil
}

// Recreate the aes key then decrypt the cipherText
func decrypt(bPriKey *ecdsa.PrivateKey, cap *capsule, pubX *ecdsa.PublicKey, cipherText []byte) (plainText []byte, err error) {
	keyBytes, err := DecryptKeyGen(bPriKey, cap, pubX)
	if err != nil {
		return nil, err
	}

	// recreate aes key = G((E' * V')^d)
	key := hex.EncodeToString(keyBytes)

	// use aes gcm to decrypt
	// mark keyBytes[:12] as nonce
	plainText, err = GCMDecrypt(cipherText, key[:32], keyBytes[:12], nil)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

func DecryptKeyGen(bPriKey *ecdsa.PrivateKey, cap *capsule, pubX *ecdsa.PublicKey) (keyBytes []byte, err error) {
	// S = X_A^{sk_B}
	S := curve.PointScalarMul(pubX, bPriKey.D)
	// recreate d = H3(X_A || pk_B || S)
	d := utils.HashToCurve(
		utils.ConcatBytes(
			utils.ConcatBytes(
				curve.PointToBytes(pubX),
				curve.PointToBytes(&bPriKey.PublicKey)),
			curve.PointToBytes(S)))
	point := curve.PointScalarMul(
		curve.PointScalarAdd(cap.E, cap.V), d)
	keyBytes, err = utils.Sha3Hash(curve.PointToBytes(point))
	if err != nil {
		return nil, err
	}
	return keyBytes, nil
}

// Decrypt with context verification
func decryptWithContext(bPriKey *ecdsa.PrivateKey, cap *capsule, pubX *ecdsa.PublicKey, cipherText []byte, context []byte) (plainText []byte, err error) {
	keyBytes, err := DecryptKeyGen(bPriKey, cap, pubX)
	if err != nil {
		return nil, err
	}

	// recreate aes key = G((E' * V')^d)
	key := hex.EncodeToString(keyBytes)

	// use aes gcm to decrypt with context verification
	// mark keyBytes[:12] as nonce
	plainText, err = GCMDecrypt(cipherText, key[:32], keyBytes[:12], context)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

// Recreate aes key
func RecreateAESKeyByOwner(capsuleBytes []byte, aPriKey *ecdsa.PrivateKey) (keyBytes []byte, err error) {
	decodeCapsule, err := decodeCapsule(capsuleBytes)
	if err != nil {
		return nil, err
	}

	point1 := curve.PointScalarAdd(decodeCapsule.E, decodeCapsule.V)
	point := curve.PointScalarMul(point1, aPriKey.D)
	// generate aes key
	keyBytes, err = utils.Sha3Hash(curve.PointToBytes(point))
	if err != nil {
		return nil, err
	}
	return keyBytes, nil
}

// Decrypt by my own private key
func DecryptByOwner(aPriKey *ecdsa.PrivateKey, capsuleBytes []byte, cipherText []byte) (plainText []byte, err error) {
	keyBytes, err := RecreateAESKeyByOwner(capsuleBytes, aPriKey)
	if err != nil {
		return nil, err
	}

	key := hex.EncodeToString(keyBytes)
	// use aes gcm algorithm to decrypt
	// mark keyBytes[:12] as nonce
	plainText, err = GCMDecrypt(cipherText, key[:32], keyBytes[:12], nil)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

func DecryptKeyGenByCapsule(bPriKey *ecdsa.PrivateKey, cap []byte, pubX *ecdsa.PublicKey) (keyBytes []byte, err error) {
	decodeCapsule, err := decodeCapsule(cap)
	if err != nil {
		return nil, err
	}
	// S = X_A^{sk_B}
	S := curve.PointScalarMul(pubX, bPriKey.D)
	// recreate d = H3(X_A || pk_B || S)
	d := utils.HashToCurve(
		utils.ConcatBytes(
			utils.ConcatBytes(
				curve.PointToBytes(pubX),
				curve.PointToBytes(&bPriKey.PublicKey)),
			curve.PointToBytes(S)))
	point := curve.PointScalarMul(
		curve.PointScalarAdd(decodeCapsule.E, decodeCapsule.V), d)
	keyBytes, err = utils.Sha3Hash(curve.PointToBytes(point))
	if err != nil {
		return nil, err
	}
	return keyBytes, nil
}
