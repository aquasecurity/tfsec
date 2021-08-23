package aws

import (
	"github.com/aquasecurity/defsec/provider/aws/ec2"
	"github.com/aquasecurity/defsec/provider/aws/s3"
)

type AWS struct {
	S3  s3.S3
	EC2 ec2.EC2
}
