package codebuild

import (
	"github.com/aquasecurity/defsec/provider/aws/codebuild"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) codebuild.CodeBuild {
	return codebuild.CodeBuild{}
}
