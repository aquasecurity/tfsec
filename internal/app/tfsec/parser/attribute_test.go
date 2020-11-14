package parser

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_AttributeStartsWith(t *testing.T) {
	var tests = []struct {
		name           string
		source         string
		checkAttribute string
		checkValue     string
		expectedResult bool
	}{
		{
			name: "bucket name starts with bucket",
			source: `
resource "aws_s3_bucket" "my-bucket" {
 	bucket_name = "bucketName"
}`,
			checkAttribute: "bucket_name",
			checkValue:     "bucket",
			expectedResult: true,
		},
		{
			name: "bucket acl starts with public",
			source: `
resource "aws_s3_bucket" "my-bucket" {
 	bucket_name = "bucketName"
	acl = "public-read"
}`,
			checkAttribute: "acl",
			checkValue:     "public",
			expectedResult: true,
		},
		{
			name: "bucket name doesn't start with secret",
			source: `
resource "aws_s3_bucket" "my-bucket" {
 	bucket_name = "bucketName"
	acl = "public-read"
	logging {
		target_bucket = aws_s3_bucket.log_bucket.id
		target_prefix = "log/"
	}
}`,
			checkAttribute: "bucket_name",
			checkValue:     "secret_",
			expectedResult: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			blocks := createBlocksFromSource(test.source)
			for _, block := range blocks {
				if !block.HasChild(test.checkAttribute) {
					t.Fail()
				}
				attr := block.GetAttribute(test.checkAttribute)
				assert.Equal(t, attr.StartsWith(test.checkValue), test.expectedResult)
			}
		})
	}
}

func Test_AttributeEndsWith(t *testing.T) {
	var tests = []struct {
		name           string
		source         string
		checkAttribute string
		checkValue     string
		expectedResult bool
	}{
		{
			name: "bucket name ends with Name",
			source: `
resource "aws_s3_bucket" "my-bucket" {
 	bucket_name = "bucketName"
}`,
			checkAttribute: "bucket_name",
			checkValue:     "Name",
			expectedResult: true,
		},
		{
			name: "bucket acl ends with read not Read",
			source: `
resource "aws_s3_bucket" "my-bucket" {
 	bucket_name = "bucketName"
	acl = "public-read"
}`,
			checkAttribute: "acl",
			checkValue:     "Read",
			expectedResult: false,
		},
		{
			name: "bucket name doesn't end with bucket",
			source: `
resource "aws_s3_bucket" "my-bucket" {
 	bucket_name = "bucketName"
	acl = "public-read"
	logging {
		target_bucket = aws_s3_bucket.log_bucket.id
		target_prefix = "log/"
	}
}`,
			checkAttribute: "bucket_name",
			checkValue:     "_bucket",
			expectedResult: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			blocks := createBlocksFromSource(test.source)
			for _, block := range blocks {
				if !block.HasChild(test.checkAttribute) {
					t.Fail()
				}
				attr := block.GetAttribute(test.checkAttribute)
				assert.Equal(t, attr.EndsWith(test.checkValue), test.expectedResult)
			}
		})
	}
}

func Test_AttributeContains(t *testing.T) {
	var tests = []struct {
		name           string
		source         string
		checkAttribute string
		checkValue     string
		expectedResult bool
	}{
		{
			name: "bucket name contains Name",
			source: `
resource "aws_s3_bucket" "my-bucket" {
 	bucket_name = "bucketName"
}`,
			checkAttribute: "bucket_name",
			checkValue:     "etNa",
			expectedResult: true,
		},
		{
			name: "bucket acl doesn't contain private",
			source: `
resource "aws_s3_bucket" "my-bucket" {
 	bucket_name = "bucketName"
	acl = "public-read"
}`,
			checkAttribute: "acl",
			checkValue:     "private",
			expectedResult: false,
		},
		{
			name: "tags attribute is a map with a Department key",
			source: `
resource "aws_s3_bucket" "my-bucket" {
 	bucket_name = "bucketName"
	acl = "public-read"
	tags = {
		Department = "Finance"
	}
}`,
			checkAttribute: "tags",
			checkValue:     "Department",
			expectedResult: true,
		},
		{
			name: "cidr_block has expected subnet",
			source: `
resource "aws_security_group" "my-security_group" {
	cidr_block = ["10.0.0.0/16", "172.0.0.0/8" ] 
}`,
			checkAttribute: "cidr_block",
			checkValue:     "172.0.0.0/8",
			expectedResult: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			blocks := createBlocksFromSource(test.source)
			for _, block := range blocks {
				if !block.HasChild(test.checkAttribute) {
					t.Fail()
				}
				attr := block.GetAttribute(test.checkAttribute)
				assert.Equal(t, attr.Contains(test.checkValue), test.expectedResult)
			}
		})
	}
}

func Test_AttributeIsAny(t *testing.T) {
	var tests []struct {
		name           string
		source         string
		checkAttribute string
		checkValue     []interface{}
		expectedResult bool
	} = []struct {
		name           string
		source         string
		checkAttribute string
		checkValue     []interface{}
		expectedResult bool
	}{
		{
			name: "bucket acl is not one of the specified acls",
			source: `
resource "aws_s3_bucket" "my-bucket" {
 	bucket_name = "bucketName"
	acl = "public-read"
}`,
			checkAttribute: "acl",
			checkValue:     []interface{}{"private", "authenticated-read"},
			expectedResult: false,
		},
		{
			name: "bucket acl is one of the specified acls",
			source: `
resource "aws_s3_bucket" "my-bucket" {
 	bucket_name = "bucketName"
	acl = "private"
}`,
			checkAttribute: "acl",
			checkValue:     []interface{}{"private", "authenticated-read"},
			expectedResult: true,
		},
		{
			name: "is is one of the provided valued",
			source: `
resource "aws_security_group" "my-security_group" {
	count = 1
}`,
			checkAttribute: "count",
			checkValue:     []interface{}{1, 2},
			expectedResult: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			blocks := createBlocksFromSource(test.source)
			for _, block := range blocks {
				if !block.HasChild(test.checkAttribute) {
					t.Fail()
				}
				attr := block.GetAttribute(test.checkAttribute)
				assert.Equal(t, attr.IsAny(test.checkValue...), test.expectedResult)
			}
		})
	}
}

func Test_AttributeIsNone(t *testing.T) {
	var tests = []struct {
		name           string
		source         string
		checkAttribute string
		checkValue     []interface{}
		expectedResult bool
	}{
		{
			name: "bucket acl is not one of the specified acls",
			source: `
resource "aws_s3_bucket" "my-bucket" {
 	bucket_name = "bucketName"
	acl = "public-read"
}`,
			checkAttribute: "acl",
			checkValue:     []interface{}{"private", "authenticated-read"},
			expectedResult: true,
		},
		{
			name: "bucket acl is one of the specified acls",
			source: `
resource "aws_s3_bucket" "my-bucket" {
 	bucket_name = "bucketName"
	acl = "private"
}`,
			checkAttribute: "acl",
			checkValue:     []interface{}{"private", "authenticated-read"},
			expectedResult: false,
		},
		{
			name: "count is non-of the provided values",
			source: `
resource "aws_security_group" "my-security_group" {
	count = 0
}`,
			checkAttribute: "count",
			checkValue:     []interface{}{1, 2},
			expectedResult: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			blocks := createBlocksFromSource(test.source)
			for _, block := range blocks {
				if !block.HasChild(test.checkAttribute) {
					t.Fail()
				}
				attr := block.GetAttribute(test.checkAttribute)
				assert.Equal(t, attr.IsNone(test.checkValue...), test.expectedResult)
			}
		})
	}
}

func Test_AttributeIsEmpty(t *testing.T) {
	var tests = []struct {
		name           string
		source         string
		checkAttribute string
		checkValue     []interface{}
		expectedResult bool
	}{
		{
			name: "bucket acl is not empty",
			source: `
resource "aws_s3_bucket" "my-bucket" {
 	bucket_name = "bucketName"
	acl = "public-read"
}`,
			checkAttribute: "acl",
			expectedResult: false,
		},
		{
			name: "bucket acl is empty",
			source: `
resource "aws_s3_bucket" "my-bucket" {
 	bucket_name = "bucketName"
	acl = ""
}`,
			checkAttribute: "acl",
			expectedResult: true,
		},
		{
			name: "tags is not empty",
			source: `
resource "aws_s3_bucket" "my-bucket" {
 	bucket_name = "bucketName"
	acl = "public-read"
	tags = {
		Department = "Finance"
	}
}`,
			checkAttribute: "tags",
			expectedResult: false,
		},
		{
			name: "tags is empty",
			source: `
resource "aws_s3_bucket" "my-bucket" {
 	bucket_name = "bucketName"
	acl = "public-read"
	tags = {
	}
}`,
			checkAttribute: "tags",
			expectedResult: true,
		},
		{
			name: "cidr is not empty",
			source: `
resource "aws_security_group_rule" "example" {
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = "sg-123456"
}`,
			checkAttribute: "cidr_blocks",
			expectedResult: false,
		},
		{
			name: "cidr is empty",
			source: `
resource "aws_security_group_rule" "example" {
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "tcp"
  cidr_blocks       = []
  security_group_id = "sg-123456"
}`,
			checkAttribute: "cidr_blocks",
			expectedResult: true,
		},
		{
			name: "from_port_is_not_empty",
			source: `
resource "aws_security_group_rule" "example" {
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "tcp"
  cidr_blocks       = []
  security_group_id = "sg-123456"
}`,
			checkAttribute: "from_port",
			expectedResult: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			blocks := createBlocksFromSource(test.source)
			for _, block := range blocks {
				if !block.HasChild(test.checkAttribute) {
					t.Fail()
				}
				attr := block.GetAttribute(test.checkAttribute)
				assert.Equal(t, attr.IsEmpty(), test.expectedResult)
			}
		})
	}
}

func Test_AttributeIsLessThan(t *testing.T) {
	var tests = []struct {
		name           string
		source         string
		checkAttribute string
		checkValue     int
		expectedResult bool
	}{
		{
			name: "check attribute is less than check value",
			source: `
resource "numerical_something" "my-bucket" {
	value = 100
}`,
			checkAttribute: "value",
			checkValue:     200,
			expectedResult: true,
		},
		{
			name: "check attribute is not less than check value",
			source: `
resource "numerical_something" "my-bucket" {
	value = 100
}`,
			checkAttribute: "value",
			checkValue:     50,
			expectedResult: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			blocks := createBlocksFromSource(test.source)
			for _, block := range blocks {
				if !block.HasChild(test.checkAttribute) {
					t.Fail()
				}
				attr := block.GetAttribute(test.checkAttribute)
				assert.Equal(t, attr.LessThan(test.checkValue), test.expectedResult)
			}
		})
	}
}

func Test_AttributeIsLessThanOrEqual(t *testing.T) {
	var tests = []struct {
		name           string
		source         string
		checkAttribute string
		checkValue     int
		expectedResult bool
	}{
		{
			name: "check attribute is less than or equal check value",
			source: `
resource "numerical_something" "my-bucket" {
	value = 100
}`,
			checkAttribute: "value",
			checkValue:     100,
			expectedResult: true,
		},
		{
			name: "check attribute is not less than check value",
			source: `
resource "numerical_something" "my-bucket" {
	value = 100
}`,
			checkAttribute: "value",
			checkValue:     50,
			expectedResult: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			blocks := createBlocksFromSource(test.source)
			for _, block := range blocks {
				if !block.HasChild(test.checkAttribute) {
					t.Fail()
				}
				attr := block.GetAttribute(test.checkAttribute)
				assert.Equal(t, attr.LessThanOrEqualTo(test.checkValue), test.expectedResult)
			}
		})
	}
}
