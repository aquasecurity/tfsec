package repositories

import (
	"github.com/aquasecurity/defsec/provider/github"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) []github.Repository {
	return nil
}
