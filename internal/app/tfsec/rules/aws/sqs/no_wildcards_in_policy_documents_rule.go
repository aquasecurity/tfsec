package sqs

import (
	"github.com/aquasecurity/defsec/rules/aws/sqs"

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
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_sqs_queue_policy"},
		Base:           sqs.CheckNoWildcardsInPolicyDocuments,
	})
}
