package custom

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func init() {
	givenCheck(`{
  "checks": [
    {
      "code": "DP011",
      "description": "Amazon S3 permissions granted to other AWS accounts in bucket policies should be restricted",
      "requiredTypes": [
        "data"
      ],
      "requiredLabels": [
        "aws_iam_policy_document"
      ],
      "severity": "ERROR",
      "matchSpec": {
        "name": "statement",
        "action": "isPresent",
        "subMatch": {
          "name": "actions",
          "action": "notContains",
          "value": "s3:DeleteBucketPolicy",
          "ignoreUndefined": true
        }
      }
    },
    {
      "code": "DP012",
      "description": "Amazon S3 permissions granted to other AWS accounts in bucket policies should be restricted",
      "requiredTypes": [
        "data"
      ],
      "requiredLabels": [
        "imaginary_resource"
      ],
      "severity": "ERROR",
      "matchSpec": {
        "name": "statement",
        "action": "isPresent",
        "subMatch": {
          "action": "and",
          "predicateMatchSpec": [
            {
              "name": "actions",
              "action": "notContains",
              "value": "s3:Foo",
              "ignoreUndefined": true
            },
            {
              "name": "actions",
              "action": "notContains",
              "value": "s3:Bar",
              "ignoreUndefined": true
            }
          ]
        }
      }
    }
  ]
}
`)
}

func TestSingleStatementMatches(t *testing.T) {
	scanResults := scanTerraform(t, `
data "aws_iam_policy_document" "bucket_policy" {
  statement {
    principals {
      type = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "s3:DeleteBucketPolicy",
      "s3:GetObjectTagging",
    ]
    resources = ["*"]
  }
}

`)
	assert.Len(t, scanResults, 1)
}

func TestMultipleStatementsSecondMatch(t *testing.T) {
	scanResults := scanTerraform(t, `
data "aws_iam_policy_document" "bucket_policy" {
  statement {}

  statement {
    principals {
      type = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "s3:DeleteBucketPolicy",
      "s3:GetObjectTagging",
    ]
    resources = ["*"]
  }
}
`)
	assert.Len(t, scanResults, 1)
}

func TestMultipleStatementsFirstMatch(t *testing.T) {
	scanResults := scanTerraform(t, `
data "aws_iam_policy_document" "bucket_policy" {

  statement {
    principals {
      type = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "s3:DeleteBucketPolicy",
      "s3:GetObjectTagging",
    ]
    resources = ["*"]
  }

  statement {}
}
`)
	assert.Len(t, scanResults, 1)
}

func TestNoMatches(t *testing.T) {
	scanResults := scanTerraform(t, `
data "aws_iam_policy_document" "bucket_policy" {
  statement {}
}
`)
	assert.Len(t, scanResults, 0)
}
func TestMultipleSubmatchesOntoMultipleStatemetns(t *testing.T) {
	scanResults := scanTerraform(t, `
data "imaginary_resource" "bucket_policy" {
  statement {
    actions = ["s3:Foo"]
  }
}
`)
	assert.Len(t, scanResults, 1)

	scanResults = scanTerraform(t, `
data "imaginary_resource" "bucket_policy" {
  statement {
    actions = ["s3:Bar"]
  }
}
`)
	assert.Len(t, scanResults, 1)

	scanResults = scanTerraform(t, `
data "imaginary_resource" "bucket_policy" {
  statement {}

  statement {
    actions = ["s3:Bar"]
  }
}
`)
	assert.Len(t, scanResults, 1)
}
