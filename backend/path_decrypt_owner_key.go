package backend

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathDecryptCapsuleWithOwnerKey(b *backend) *framework.Path {
	return &framework.Path{
		Pattern:         "pre/" + framework.GenericNameRegex("name") + "/decrypt/owner",
		HelpSynopsis:    "Decrypt capsule using owner's private key stored in Vault.",
		HelpDescription: "Decrypt capsule using owner's private key stored in Vault.",
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{Type: framework.TypeString},
			"capsuleBytes": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "The capsule bytes.",
			},
		},
		ExistenceCheck: b.pathExistenceCheck,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.decryptDataWithOwnerKey,
		},
	}
}
