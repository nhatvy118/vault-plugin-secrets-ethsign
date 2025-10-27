package backend

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathDecryptCapsuleWithViewerKey(b *backend) *framework.Path {
	return &framework.Path{
		Pattern:         "pre/" + framework.GenericNameRegex("name") + "/decrypt/viewer",
		HelpSynopsis:    "Decrypt re-encrypted data using viewer's private key.",
		HelpDescription: "Decrypt re-encrypted data using the viewer's private key. This endpoint requires the capsule, cfrag, and ciphertext.",

		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{Type: framework.TypeString},
			"capsuleBytes": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "The capsule bytes.",
			},
			"issuerPublicKey": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "The public key of the issuer.",
			},
		},
		ExistenceCheck: b.pathExistenceCheck,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.decryptDataWithViewerKey,
		},
	}
}
