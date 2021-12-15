package documentdb

import (
	"github.com/aquasecurity/defsec/provider/aws/documentdb"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) documentdb.DocumentDB {
	return documentdb.DocumentDB{}
}
