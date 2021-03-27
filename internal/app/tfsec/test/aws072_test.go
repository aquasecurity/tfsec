package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSCloudfrontDistributionViewerProtocolPolicyHTTPS(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "Check does not pass when Viewer Protocol Policy is not only HTTPS in default cache",
			source: `
resource "aws_cloudfront_distribution" "bad_example" {
	// other cloudfront distribution config

	default_cache_behavior {
		// other cache config

		viewer_protocol_policy = "allow-all" // including HTTP
	}
}
`,
			mustIncludeResultCode: checks.AWSCloudfrontDistributionViewerProtocolPolicyHTTPS,
		},
		{
			name: "Check does not pass when Viewer Protocol Policy is not only HTTPS in ordered cache",
			source: `
resource "aws_cloudfront_distribution" "bad_example" {
	// other cloudfront distribution config

	default_cache_behavior {
		// other cache config

		viewer_protocol_policy = "https-only" // HTTPS by default...
	}

	ordered_cache_behavior {
		// other cache config

		viewer_protocol_policy = "allow-all" // ...but HTTP for some other resources
	}
}
`,
			mustIncludeResultCode: checks.AWSCloudfrontDistributionViewerProtocolPolicyHTTPS,
		},
		{
			name: "Check does not pass when Viewer Protocol Policy is not only HTTPS in one of ordered caches",
			source: `
resource "aws_cloudfront_distribution" "bad_example" {
	// other cloudfront distribution config

	default_cache_behavior {
		// other cache config

		viewer_protocol_policy = "https-only" // HTTPS by default...
	}

	ordered_cache_behavior {
		// other cache config

		viewer_protocol_policy = "https-only"
	}

	ordered_cache_behavior {
		// other cache config

		viewer_protocol_policy = "allow-all" // ...but HTTP for some other resources
	}
}
`,
			mustIncludeResultCode: checks.AWSCloudfrontDistributionViewerProtocolPolicyHTTPS,
		},
		{
			name: "Check does pass when Viewer Protocol Policy is HTTPS only in default cache",
			source: `
resource "aws_cloudfront_distribution" "good_example" {
	// other cloudfront distribution config

	default_cache_behavior {
		// other cache config

		viewer_protocol_policy = "https-only" // including HTTP
	}
}
`,
			mustExcludeResultCode: checks.AWSCloudfrontDistributionViewerProtocolPolicyHTTPS,
		},
		{
			name: "Check does pass when Viewer Protocol Policy is set to redirect to HTTPS in default cache",
			source: `
resource "aws_cloudfront_distribution" "good_example" {
	// other cloudfront distribution config

	default_cache_behavior {
		// other cache config

		viewer_protocol_policy = "redirect-to-https" // including HTTP
	}
}
`,
			mustExcludeResultCode: checks.AWSCloudfrontDistributionViewerProtocolPolicyHTTPS,
		},
		{
			name: "Check does pass when Viewer Protocol Policy is set to either redirect to HTTPS or HTTPS only in all cache behaviours",
			source: `
resource "aws_cloudfront_distribution" "good_example" {
	// other cloudfront distribution config

	default_cache_behavior {
		// other cache config

		viewer_protocol_policy = "https-only" 
	}

	ordered_cache_behavior {
		// other cache config

		viewer_protocol_policy = "redirect-to-https"
	}

	ordered_cache_behavior {
		// other cache config

		viewer_protocol_policy = "https-only"
	}
}
`,
			mustExcludeResultCode: checks.AWSCloudfrontDistributionViewerProtocolPolicyHTTPS,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
