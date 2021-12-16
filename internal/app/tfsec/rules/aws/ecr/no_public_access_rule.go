package ecr

import (
	"encoding/json"
	"strings"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/ecr"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/iam"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
 resource "aws_ecr_repository" "foo" {
   name = "bar"
 }
 
 resource "aws_ecr_repository_policy" "foopolicy" {
   repository = aws_ecr_repository.foo.name
 
   policy = <<EOF
 {
     "Version": "2008-10-17",
     "Statement": [
         {
             "Sid": "new policy",
             "Effect": "Allow",
             "Principal": "*",
             "Action": [
                 "ecr:GetDownloadUrlForLayer",
                 "ecr:BatchGetImage",
                 "ecr:BatchCheckLayerAvailability",
                 "ecr:PutImage",
                 "ecr:InitiateLayerUpload",
                 "ecr:UploadLayerPart",
                 "ecr:CompleteLayerUpload",
                 "ecr:DescribeRepositories",
                 "ecr:GetRepositoryPolicy",
                 "ecr:ListImages",
                 "ecr:DeleteRepository",
                 "ecr:BatchDeleteImage",
                 "ecr:SetRepositoryPolicy",
                 "ecr:DeleteRepositoryPolicy"
             ]
         }
     ]
 }
 EOF
 }
 `},
		GoodExample: []string{`
 resource "aws_ecr_repository" "foo" {
   name = "bar"
 }
 
 resource "aws_ecr_repository_policy" "foopolicy" {
   repository = aws_ecr_repository.foo.name
 
   policy = <<EOF
 {
     "Version": "2008-10-17",
     "Statement": [
         {
             "Sid": "new policy",
             "Effect": "Allow",
             "Principal": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root",
             "Action": [
                 "ecr:GetDownloadUrlForLayer",
                 "ecr:BatchGetImage",
                 "ecr:BatchCheckLayerAvailability",
                 "ecr:PutImage",
                 "ecr:InitiateLayerUpload",
                 "ecr:UploadLayerPart",
                 "ecr:CompleteLayerUpload",
                 "ecr:DescribeRepositories",
                 "ecr:GetRepositoryPolicy",
                 "ecr:ListImages",
                 "ecr:DeleteRepository",
                 "ecr:BatchDeleteImage",
                 "ecr:SetRepositoryPolicy",
                 "ecr:DeleteRepositoryPolicy"
             ]
         }
     ]
 }
 EOF
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository_policy#policy",
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"aws_ecr_repository_policy",
		},
		Base: ecr.CheckNoPublicAccess,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			policyAttr := resourceBlock.GetAttribute("policy")
			if policyAttr.IsNil() || !policyAttr.IsString() {
				return
			}

			var document iam.PolicyDocument
			if err := json.Unmarshal([]byte(policyAttr.Value().AsString()), &document); err != nil {
				debug.Log("Error decoding IAM policy JSON at %s: %s", policyAttr.Range(), err)
				return
			}

			for _, statement := range document.Statements {
				var hasECRAction bool
				for _, action := range statement.Action {
					if strings.HasPrefix(action, "ecr:") {
						hasECRAction = true
						break
					}
				}
				if !hasECRAction {
					continue
				}
				for _, account := range statement.Principal.AWS {
					if account == "*" {
						results.Add("Resource provides public access to the ECR repository.", policyAttr)
					}
					return
				}
			}
			return results
		},
	})
}
