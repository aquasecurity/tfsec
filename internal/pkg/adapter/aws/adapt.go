package aws

import (
	"github.com/aquasecurity/defsec/provider/aws"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/apigateway"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/athena"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/autoscaling"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/cloudfront"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/cloudtrail"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/cloudwatch"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/codebuild"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/config"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/documentdb"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/dynamodb"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/ebs"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/ec2"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/ecr"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/ecs"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/efs"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/eks"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/elasticache"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/elasticsearch"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/elb"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/iam"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/kinesis"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/kms"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/lambda"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/mq"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/msk"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/neptune"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/rds"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/redshift"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/s3"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/sns"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/sqs"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/ssm"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/vpc"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/aws/workspaces"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) aws.AWS {
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
