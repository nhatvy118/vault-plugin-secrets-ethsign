package recrypt

import (
	"testing"

	"github.com/kaleido-io/vault-plugin-secrets-ethsign/pre/utils"
)

// TestE2EEncryptDecrypt tests the complete encryption and decryption flow
func TestE2EEncryptDecrypt(t *testing.T) {
	// Generate key pairs for Alice and Bob
	alicePrivKey, alicePubKey, err := utils.GenerateKeys()
	if err != nil {
		t.Fatalf("Failed to generate Alice's keys: %v", err)
	}

	bobPrivKey, bobPubKey, err := utils.GenerateKeys()
	if err != nil {
		t.Fatalf("Failed to generate Bob's keys: %v", err)
	}

	// Test data
	testData := []byte("Hello, World! This is a test message for proxy re-encryption. Hello, World! This is a test message for proxy re-encryption.  Hello, World! This is a test message for proxy re-encryption. ")
	t.Logf("Original data: %s", string(testData))

	// Step 1: Alice encrypts data for herself
	capsule, cipherText, err := Encrypt(testData, alicePubKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	t.Logf("Encryption successful. Capsule size: %d bytes, Cipher text size: %d bytes", len(capsule), len(cipherText))

	// Step 2: Alice creates a re-encryption key for Bob
	rekey, err := CreateRekey(alicePrivKey, bobPubKey)
	if err != nil {
		t.Fatalf("Failed to create rekey: %v", err)
	}
	t.Logf("Rekey created successfully. Size: %d bytes", len(rekey))

	// Step 3: Server performs re-encryption
	reCapsule, err := ReEncrypt(capsule, rekey)
	if err != nil {
		t.Fatalf("Re-encryption failed: %v", err)
	}

	decryptedData, err := Decrypt(cipherText, reCapsule, bobPrivKey)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify the decrypted data matches the original
	if string(decryptedData) != string(testData) {
		t.Errorf("Decrypted data doesn't match original. Expected: %s, Got: %s", string(testData), string(decryptedData))
	} else {
		t.Logf("Decryption successful. Decrypted data: %s", string(decryptedData))
	}
}
