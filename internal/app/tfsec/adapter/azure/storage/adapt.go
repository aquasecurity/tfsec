package storage

import (
	"github.com/aquasecurity/defsec/provider/azure/storage"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) storage.Storage {
	return storage.Storage{}
}
