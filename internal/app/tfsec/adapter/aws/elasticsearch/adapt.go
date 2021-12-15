package elasticsearch

import (
	"github.com/aquasecurity/defsec/provider/aws/elasticsearch"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) elasticsearch.Elasticsearch {
	return elasticsearch.Elasticsearch{}
}
