package datafactory

import "github.com/aquasecurity/defsec/types"

type DataFactory struct {
	types.Metadata
	DataFactories []Factory
}

type Factory struct {
	types.Metadata
	EnablePublicNetwork types.BoolValue
}


func (d *DataFactory) GetMetadata() *types.Metadata {
	return &d.Metadata
}

func (d *DataFactory) GetRawValue() interface{} {
	return nil
}    


func (f *Factory) GetMetadata() *types.Metadata {
	return &f.Metadata
}

func (f *Factory) GetRawValue() interface{} {
	return nil
}    
