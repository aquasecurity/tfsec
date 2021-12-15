package sqs

import (
	"encoding/json"
	"strings"

	"github.com/aquasecurity/defsec/rules/aws/sqs"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS047",
		BadExample: []string{`
 resource "aws_sqs_queue_policy" "bad_example" {
   queue_url = aws_sqs_queue.q.id
 
   policy = <<POLICY
 {
   "Statement": [
     {
       "Effect": "Allow",
       "Principal": "*",
       "Action": "*"
     }
   ]
 }
 POLICY
 }
 `},
		GoodExample: []string{`
 resource "aws_sqs_queue_policy" "good_example" {
   queue_url = aws_sqs_queue.q.id
 
   policy = <<POLICY
 {
   "Statement": [
     {
       "Effect": "Allow",
       "Principal": "*",
       "Action": "sqs:SendMessage"
     }
   ]
 }
 POLICY
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue_policy",
			"https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-security-best-practices.html",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_sqs_queue_policy"},
		Base:           sqs.CheckNoWildcardsInPolicyDocuments,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("policy") || !resourceBlock.GetAttribute("policy").IsString() {
				return
			}

			policyAttr := resourceBlock.GetAttribute("policy")
			rawJSON := []byte(policyAttr.Value().AsString())
			var policy struct {
				Statement []struct {
					Effect string `json:"Effect"`
					Action string `json:"Action"`
				} `json:"Statement"`
			}

			if err := json.Unmarshal(rawJSON, &policy); err == nil {
				for _, statement := range policy.Statement {
					if strings.ToLower(statement.Effect) == "allow" && (statement.Action == "*" || statement.Action == "sqs:*") {
						results.Add("SQS policy has a wildcard action specified.", policyAttr)
					}
				}
			}

			return results
		},
	})
}
