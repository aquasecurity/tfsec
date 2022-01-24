package compute

import (
	"encoding/base64"

	"github.com/aquasecurity/defsec/provider/cloudstack/compute"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) compute.Compute {
	return compute.Compute{
		Instances: adaptInstances(modules),
	}
}

func adaptInstances(modules block.Modules) []compute.Instance {
	var instances []compute.Instance
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("cloudstack_instance") {
			instances = append(instances, adaptInstance(resource))
		}
	}
	return instances
}

func adaptInstance(resource *block.Block) compute.Instance {
	userDataAttr := resource.GetAttribute("user_data")
	var encoded []byte
	var err error

	if userDataAttr.IsNotNil() && userDataAttr.IsString() {
		encoded, err = base64.StdEncoding.DecodeString(userDataAttr.Value().AsString())
		if err != nil {
			encoded = []byte(userDataAttr.Value().AsString())
		}
	}

	return compute.Instance{
		Metadata: resource.Metadata(),
		UserData: types.String(string(encoded), *resource.GetMetadata()),
	}
}
