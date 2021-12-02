package aws

import (
	"github.com/aquasecurity/defsec/provider/aws/apigateway"
	"github.com/aquasecurity/defsec/provider/aws/athena"
	"github.com/aquasecurity/defsec/provider/aws/autoscaling"
	"github.com/aquasecurity/defsec/provider/aws/cloudfront"
	"github.com/aquasecurity/defsec/provider/aws/cloudtrail"
	"github.com/aquasecurity/defsec/provider/aws/cloudwatch"
	"github.com/aquasecurity/defsec/provider/aws/codebuild"
	"github.com/aquasecurity/defsec/provider/aws/config"
	"github.com/aquasecurity/defsec/provider/aws/documentdb"
	"github.com/aquasecurity/defsec/provider/aws/dynamodb"
	"github.com/aquasecurity/defsec/provider/aws/ebs"
	"github.com/aquasecurity/defsec/provider/aws/ec2"
	"github.com/aquasecurity/defsec/provider/aws/ecr"
	"github.com/aquasecurity/defsec/provider/aws/ecs"
	"github.com/aquasecurity/defsec/provider/aws/efs"
	"github.com/aquasecurity/defsec/provider/aws/eks"
	"github.com/aquasecurity/defsec/provider/aws/elasticache"
	"github.com/aquasecurity/defsec/provider/aws/elasticsearch"
	"github.com/aquasecurity/defsec/provider/aws/elb"
	"github.com/aquasecurity/defsec/provider/aws/iam"
	"github.com/aquasecurity/defsec/provider/aws/kinesis"
	"github.com/aquasecurity/defsec/provider/aws/kms"
	"github.com/aquasecurity/defsec/provider/aws/lambda"
	"github.com/aquasecurity/defsec/provider/aws/mq"
	"github.com/aquasecurity/defsec/provider/aws/msk"
	"github.com/aquasecurity/defsec/provider/aws/neptune"
	"github.com/aquasecurity/defsec/provider/aws/rds"
	"github.com/aquasecurity/defsec/provider/aws/redshift"
	"github.com/aquasecurity/defsec/provider/aws/s3"
	"github.com/aquasecurity/defsec/provider/aws/sns"
	"github.com/aquasecurity/defsec/provider/aws/sqs"
	"github.com/aquasecurity/defsec/provider/aws/ssm"
	"github.com/aquasecurity/defsec/provider/aws/vpc"
	"github.com/aquasecurity/defsec/provider/aws/workspaces"
)

type AWS struct {
	APIGateway    apigateway.APIGateway
	Athena        athena.Athena
	Autoscaling   autoscaling.Autoscaling
	Cloudfront    cloudfront.Cloudfront
	CloudTrail    cloudtrail.CloudTrail
	CloudWatch    cloudwatch.CloudWatch
	CodeBuild     codebuild.CodeBuild
	Config        config.Config
	DocumentDB    documentdb.DocumentDB
	DynamoDB      dynamodb.DynamoDB
	EBS           ebs.EBS
	EC2           ec2.EC2
	ECR           ecr.ECR
	ECS           ecs.ECS
	EFS           efs.EFS
	EKS           eks.EKS
	ElastiCache   elasticache.ElastiCache
	Elasticsearch elasticsearch.Elasticsearch
	ELB           elb.ELB
	IAM           iam.IAM
	Kinesis       kinesis.Kinesis
	KMS           kms.KMS
	Lambda        lambda.Lambda
	MQ            mq.MQ
	MSK           msk.MSK
	Neptune       neptune.Neptune
	RDS           rds.RDS
	Redshift      redshift.Redshift
	S3            s3.S3
	SNS           sns.SNS
	SQS           sqs.SQS
	SSM           ssm.SSM
	VPC           vpc.VPC
	WorkSpaces    workspaces.WorkSpaces
}
