package sql

import (
	"github.com/aquasecurity/defsec/provider/google/sql"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) sql.SQL {
	return sql.SQL{}
}
