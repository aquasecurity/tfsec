package repositories

import (
	"github.com/aquasecurity/defsec/provider/github"
	"github.com/aquasecurity/trivy-config-parsers/terraform"
	"github.com/aquasecurity/trivy-config-parsers/types"
)

func Adapt(modules terraform.Modules) []github.Repository {
	return adaptRepositories(modules)
}

func adaptRepositories(modules terraform.Modules) []github.Repository {
	var repositories []github.Repository
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("github_repository") {
			repositories = append(repositories, adaptRepository(resource))
		}
	}
	return repositories
}

func adaptRepository(resource *terraform.Block) github.Repository {

	// visibility overrides private
	visibilityAttr := resource.GetAttribute("visibility")
	if visibilityAttr.Equals("private") || visibilityAttr.Equals("internal") {
		return github.Repository{
			Metadata: resource.GetMetadata(),
			Public:   types.Bool(false, resource.GetMetadata()),
		}
	} else if visibilityAttr.Equals("public") {
		return github.Repository{
			Metadata: resource.GetMetadata(),
			Public:   types.Bool(true, resource.GetMetadata()),
		}
	}

	privateAttr := resource.GetAttribute("private")
	if privateAttr.IsTrue() {
		return github.Repository{
			Metadata: resource.GetMetadata(),
			Public:   types.Bool(false, resource.GetMetadata()),
		}
	}

	return github.Repository{
		Metadata: resource.GetMetadata(),
		Public:   types.Bool(true, resource.GetMetadata()),
	}
}
