package utils

import (
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestPrivateKeyToStr(t *testing.T) {
	// Generate a test private key
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Test conversion to string
	privateKeyStr := PrivateKeyToStr(privateKey)
	if privateKeyStr == "" {
		t.Error("PrivateKeyToStr returned empty string")
	}

	// Test round-trip conversion
	convertedPrivateKey, err := PrivateKeyStrToKey(privateKeyStr)
	if err != nil {
		t.Fatalf("Failed to convert string back to private key: %v", err)
	}

	// Verify the private key values match
	if privateKey.D.Cmp(convertedPrivateKey.D) != 0 {
		t.Error("Private key D values don't match after round-trip conversion")
	}

	// Verify the public key coordinates match
	if privateKey.PublicKey.X.Cmp(convertedPrivateKey.PublicKey.X) != 0 {
		t.Error("Public key X coordinates don't match after round-trip conversion")
	}
	if privateKey.PublicKey.Y.Cmp(convertedPrivateKey.PublicKey.Y) != 0 {
		t.Error("Public key Y coordinates don't match after round-trip conversion")
	}
}

func TestPublicKeyToStr(t *testing.T) {
	// Generate a test private key to get its public key
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	// Test conversion to string
	publicKeyStr := PublicKeyToStr(publicKey)
	if publicKeyStr == "" {
		t.Error("PublicKeyToStr returned empty string")
	}

	// Test round-trip conversion
	convertedPublicKey, err := PublicKeyStrToKey(publicKeyStr)
	if err != nil {
		t.Fatalf("Failed to convert string back to public key: %v", err)
	}

	// Verify the public key coordinates match
	if publicKey.X.Cmp(convertedPublicKey.X) != 0 {
		t.Error("Public key X coordinates don't match after round-trip conversion")
	}
	if publicKey.Y.Cmp(convertedPublicKey.Y) != 0 {
		t.Error("Public key Y coordinates don't match after round-trip conversion")
	}
}

func TestKeyConversionRoundTrip(t *testing.T) {
	// Generate original key pair
	originalPrivateKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	originalPublicKey := &originalPrivateKey.PublicKey

	// Convert to strings
	privateKeyStr := PrivateKeyToStr(originalPrivateKey)
	publicKeyStr := PublicKeyToStr(originalPublicKey)

	// Convert back to keys
	convertedPrivateKey, err := PrivateKeyStrToKey(privateKeyStr)
	if err != nil {
		t.Fatalf("Failed to convert private key string back: %v", err)
	}
	convertedPublicKey, err := PublicKeyStrToKey(publicKeyStr)
	if err != nil {
		t.Fatalf("Failed to convert public key string back: %v", err)
	}

	// Verify private key round-trip
	if originalPrivateKey.D.Cmp(convertedPrivateKey.D) != 0 {
		t.Error("Private key D values don't match after round-trip")
	}

	// Verify public key round-trip
	if originalPublicKey.X.Cmp(convertedPublicKey.X) != 0 {
		t.Error("Public key X coordinates don't match after round-trip")
	}
	if originalPublicKey.Y.Cmp(convertedPublicKey.Y) != 0 {
		t.Error("Public key Y coordinates don't match after round-trip")
	}

	// Verify that the converted private key's public key matches the converted public key
	if convertedPrivateKey.PublicKey.X.Cmp(convertedPublicKey.X) != 0 {
		t.Error("Converted private key's public X doesn't match converted public key X")
	}
	if convertedPrivateKey.PublicKey.Y.Cmp(convertedPublicKey.Y) != 0 {
		t.Error("Converted private key's public Y doesn't match converted public key Y")
	}
}
