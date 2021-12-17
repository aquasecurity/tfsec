package database

import (
	"github.com/aquasecurity/defsec/provider/azure/database"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) database.Database {
	return database.Database{}
}
