package github

import (
	"github.com/aquasecurity/defsec/provider/github"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/github/repositories"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) github.GitHub {
	return github.GitHub{
		Repositories: repositories.Adapt(modules),
	}
}
