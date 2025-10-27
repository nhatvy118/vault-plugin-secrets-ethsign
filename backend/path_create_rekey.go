package backend

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCreateRekey(b *backend) *framework.Path {
	return &framework.Path{
		Pattern:         "pre/" + framework.GenericNameRegex("name") + "/rekey",
		HelpSynopsis:    "Create a rekey fragment.",
		HelpDescription: "Create a rekey fragment (kfrag) using the private key and public key.",

		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{Type: framework.TypeString},
			"publicKey": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "The public key of viewer account.",
			},
		},
		ExistenceCheck: b.pathExistenceCheck,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.createRekey,
		},
	}
}
