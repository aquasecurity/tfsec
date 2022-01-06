package kms

import (
	"github.com/aquasecurity/defsec/rules/google/kms"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
 resource "google_kms_key_ring" "keyring" {
   name     = "keyring-example"
   location = "global"
 }
 
 resource "google_kms_crypto_key" "example-key" {
   name            = "crypto-key-example"
   key_ring        = google_kms_key_ring.keyring.id
   rotation_period = "15552000s"
 
   lifecycle {
     prevent_destroy = true
   }
 }
 `},
		GoodExample: []string{`
 resource "google_kms_key_ring" "keyring" {
   name     = "keyring-example"
   location = "global"
 }
 
 resource "google_kms_crypto_key" "example-key" {
   name            = "crypto-key-example"
   key_ring        = google_kms_key_ring.keyring.id
   rotation_period = "7776000s"
 
   lifecycle {
     prevent_destroy = true
   }
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/kms_crypto_key#rotation_period",
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"google_kms_crypto_key",
		},
		Base: kms.CheckRotateKmsKeys,
	})
}
