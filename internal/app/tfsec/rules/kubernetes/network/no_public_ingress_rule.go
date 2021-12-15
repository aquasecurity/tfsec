package network

// ATTENTION!
// This rule was autogenerated!
// Before making changes, consider updating the generator.

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/cidr"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
 resource "kubernetes_network_policy" "bad_example" {
   metadata {
     name      = "terraform-example-network-policy"
     namespace = "default"
   }
 
   spec {
     pod_selector {
       match_expressions {
         key      = "name"
         operator = "In"
         values   = ["webfront", "api"]
       }
     }
 
     ingress {
       ports {
         port     = "http"
         protocol = "TCP"
       }
       ports {
         port     = "8125"
         protocol = "UDP"
       }
 
       from {
         ip_block {
           cidr = "0.0.0.0/0"
           except = [
             "10.0.0.0/24",
             "10.0.1.0/24",
           ]
         }
       }
     }
 
     egress {
       ports {
         port     = "http"
         protocol = "TCP"
       }
       ports {
         port     = "8125"
         protocol = "UDP"
       }
 
       to {
         ip_block {
           cidr = "0.0.0.0/0"
           except = [
             "10.0.0.0/24",
             "10.0.1.0/24",
           ]
         }
       }
     }
 
     policy_types = ["Ingress", "Egress"]
   }
 }
 `},
		GoodExample: []string{`
 resource "kubernetes_network_policy" "good_example" {
   metadata {
     name      = "terraform-example-network-policy"
     namespace = "default"
   }
 
   spec {
     pod_selector {
       match_expressions {
         key      = "name"
         operator = "In"
         values   = ["webfront", "api"]
       }
     }
 
     ingress {
       ports {
         port     = "http"
         protocol = "TCP"
       }
       ports {
         port     = "8125"
         protocol = "UDP"
       }
 
       from {
         ip_block {
           cidr = "10.0.0.0/16"
           except = [
             "10.0.0.0/24",
             "10.0.1.0/24",
           ]
         }
       }
     }
 
     egress {
       ports {
         port     = "http"
         protocol = "TCP"
       }
       ports {
         port     = "8125"
         protocol = "UDP"
       }
 
       to {
         ip_block {
           cidr = "0.0.0.0/0"
           except = [
             "10.0.0.0/24",
             "10.0.1.0/24",
           ]
         }
       }
     }
 
     policy_types = ["Ingress", "Egress"]
   }
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/network_policy#spec.ingress.from.ip_block.cidr",
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"kubernetes_network_policy",
		},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			ingressBlock := resourceBlock.GetBlock("spec").GetBlock("ingress")
			if ingressBlock.IsNil() || len(ingressBlock.GetBlocks("from")) == 0 {
				results.Add("Resource allows all ingress traffic by default", ?)
				return
			}

			for _, from := range ingressBlock.GetBlocks("from") {
				if cidrAttr := from.GetBlock("ip_block").GetAttribute("cidr"); cidrAttr.IsString() {
					if cidr.IsAttributeOpen(cidrAttr) {
						results.Add("Resource allows ingress traffic from the internet", ?)
					}
				}
			}
			return results
		},
	})
}
