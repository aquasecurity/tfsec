package compute

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/cidr"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "GCP003",
		Service:   "compute",
		ShortCode: "no-public-ingress",
		Documentation: rule.RuleDocumentation{
			Summary:    "An inbound firewall rule allows traffic from /0.",
			Impact:     "The port is exposed for ingress from the internet",
			Resolution: "Set a more restrictive cidr range",
			Explanation: `
Network security rules should not use very broad subnets.

Where possible, segments should be broken into smaller subnets and avoid using the <code>/0</code> subnet.
`,
			BadExample: []string{`
resource "google_compute_firewall" "bad_example" {
	source_ranges = ["0.0.0.0/0"]
}`},
			GoodExample: []string{`
resource "google_compute_firewall" "good_example" {
	source_ranges = ["1.2.3.4/32"]
}`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall#source_ranges",
				"https://cloud.google.com/vpc/docs/using-firewalls",
				"https://www.terraform.io/docs/providers/google/r/compute_firewall.html",
			},
		},
		Provider:        provider.GoogleProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_compute_firewall"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if sourceRanges := resourceBlock.GetAttribute("source_ranges"); sourceRanges.IsNotNil() {
				if cidr.IsAttributeOpen(sourceRanges) {
					set.AddResult().
						WithDescription("Resource '%s' defines a fully open inbound firewall rule.", resourceBlock.FullName()).
						WithAttribute(sourceRanges)
				}
			}

		},
	})

}
