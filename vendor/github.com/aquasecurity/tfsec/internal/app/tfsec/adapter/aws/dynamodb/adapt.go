package dynamodb

import (
	"github.com/aquasecurity/defsec/provider/aws/dynamodb"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) dynamodb.DynamoDB {
	return dynamodb.DynamoDB{}
}
