package kms

import (
	"strconv"

	"github.com/aquasecurity/defsec/rules/google/kms"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
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
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			rotationAttr := resourceBlock.GetAttribute("rotation_period")
			if rotationAttr.IsNil() || (rotationAttr.IsResolvable() && rotationAttr.IsEmpty()) {
				results.Add("Resource does not have key rotation enabled.", resourceBlock)
				return
			}
			if !rotationAttr.IsResolvable() || !rotationAttr.IsString() {
				return
			}

			rotationStr := rotationAttr.Value().AsString()
			if rotationStr[len(rotationStr)-1:] != "s" {
				return
			}
			seconds, err := strconv.Atoi(rotationStr[:len(rotationStr)-1])
			if err != nil {
				return
			}
			if seconds > 7776000 {
				results.Add("Resource has a key rotation of greater than 90 days.", resourceBlock)
			}
			return results
		},
	})
}
