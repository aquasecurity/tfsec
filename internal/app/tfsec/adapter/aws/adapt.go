package aws

import (
	"github.com/aquasecurity/defsec/provider/aws"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/apigateway"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/athena"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/autoscaling"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/cloudfront"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/cloudtrail"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/cloudwatch"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/codebuild"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/config"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/documentdb"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/dynamodb"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/ebs"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/ec2"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/ecr"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/ecs"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/efs"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/eks"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/elasticache"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/elasticsearch"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/elb"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/iam"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/kinesis"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/kms"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/lambda"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/mq"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/msk"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/neptune"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/rds"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/redshift"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/s3"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/sns"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/sqs"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/ssm"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/vpc"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/aws/workspaces"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) aws.AWS {
	return aws.AWS{
		APIGateway:    apigateway.Adapt(modules),
		Athena:        athena.Adapt(modules),
		Autoscaling:   autoscaling.Adapt(modules),
		Cloudfront:    cloudfront.Adapt(modules),
		CloudTrail:    cloudtrail.Adapt(modules),
		CloudWatch:    cloudwatch.Adapt(modules),
		CodeBuild:     codebuild.Adapt(modules),
		Config:        config.Adapt(modules),
		DocumentDB:    documentdb.Adapt(modules),
		DynamoDB:      dynamodb.Adapt(modules),
		EBS:           ebs.Adapt(modules),
		EC2:           ec2.Adapt(modules),
		ECR:           ecr.Adapt(modules),
		ECS:           ecs.Adapt(modules),
		EFS:           efs.Adapt(modules),
		EKS:           eks.Adapt(modules),
		ElastiCache:   elasticache.Adapt(modules),
		Elasticsearch: elasticsearch.Adapt(modules),
		ELB:           elb.Adapt(modules),
		IAM:           iam.Adapt(modules),
		Kinesis:       kinesis.Adapt(modules),
		KMS:           kms.Adapt(modules),
		Lambda:        lambda.Adapt(modules),
		MQ:            mq.Adapt(modules),
		MSK:           msk.Adapt(modules),
		Neptune:       neptune.Adapt(modules),
		RDS:           rds.Adapt(modules),
		Redshift:      redshift.Adapt(modules),
		S3:            s3.Adapt(modules),
		SNS:           sns.Adapt(modules),
		SQS:           sqs.Adapt(modules),
		SSM:           ssm.Adapt(modules),
		VPC:           vpc.Adapt(modules),
		WorkSpaces:    workspaces.Adapt(modules),
	}
}
