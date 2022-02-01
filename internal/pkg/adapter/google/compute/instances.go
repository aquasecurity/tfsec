package compute

import (
	"github.com/aquasecurity/defsec/provider/google/compute"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
	"github.com/zclconf/go-cty/cty"
)

func adaptInstances(modules block.Modules) (instances []compute.Instance) {

	for _, instanceBlock := range modules.GetResourcesByType("google_compute_instance") {

		instance := compute.Instance{
			Metadata: instanceBlock.Metadata(),
			Name:     types.StringDefault("", instanceBlock.Metadata()),
			ShieldedVM: compute.ShieldedVMConfig{
				Metadata:                   instanceBlock.Metadata(),
				SecureBootEnabled:          types.BoolDefault(false, instanceBlock.Metadata()),
				IntegrityMonitoringEnabled: types.BoolDefault(false, instanceBlock.Metadata()),
				VTPMEnabled:                types.BoolDefault(false, instanceBlock.Metadata()),
			},
			ServiceAccount: compute.ServiceAccount{
				Metadata: instanceBlock.Metadata(),
				Email:    types.StringDefault("", instanceBlock.Metadata()),
				Scopes:   nil,
			},
			CanIPForward:                instanceBlock.GetAttribute("can_ip_forward").AsBoolValueOrDefault(false, instanceBlock),
			OSLoginEnabled:              types.BoolDefault(true, instanceBlock.Metadata()),
			EnableProjectSSHKeyBlocking: types.BoolDefault(false, instanceBlock.Metadata()),
			EnableSerialPort:            types.BoolDefault(false, instanceBlock.Metadata()),
			NetworkInterfaces:           nil,
			BootDisks:                   nil,
			AttachedDisks:               nil,
		}
		instance.Metadata = instanceBlock.Metadata()

		// network interfaces
		for _, networkInterfaceBlock := range instanceBlock.GetBlocks("network_interface") {
			var ni compute.NetworkInterface
			ni.Metadata = networkInterfaceBlock.Metadata()
			ni.HasPublicIP = types.BoolDefault(false, networkInterfaceBlock.Metadata())
			if accessConfigBlock := networkInterfaceBlock.GetBlock("access_config"); accessConfigBlock.IsNotNil() {
				ni.HasPublicIP = types.Bool(true, accessConfigBlock.Metadata())
			}
			instance.NetworkInterfaces = append(instance.NetworkInterfaces, ni)
		}

		// vm shielding
		if shieldedBlock := instanceBlock.GetBlock("shielded_instance_config"); shieldedBlock.IsNotNil() {
			instance.ShieldedVM.Metadata = shieldedBlock.Metadata()
			instance.ShieldedVM.IntegrityMonitoringEnabled = shieldedBlock.GetAttribute("enable_integrity_monitoring").AsBoolValueOrDefault(true, shieldedBlock)
			instance.ShieldedVM.VTPMEnabled = shieldedBlock.GetAttribute("enable_vtpm").AsBoolValueOrDefault(true, shieldedBlock)
			instance.ShieldedVM.SecureBootEnabled = shieldedBlock.GetAttribute("enable_secure_boot").AsBoolValueOrDefault(false, shieldedBlock)
		}

		if serviceAccountBlock := instanceBlock.GetBlock("service_account"); serviceAccountBlock.IsNotNil() {
			instance.ServiceAccount.Metadata = serviceAccountBlock.Metadata()
			instance.ServiceAccount.Email = serviceAccountBlock.GetAttribute("email").AsStringValueOrDefault("", serviceAccountBlock)
		}

		// metadata
		if metadataAttr := instanceBlock.GetAttribute("metadata"); metadataAttr.IsNotNil() {
			if val := metadataAttr.MapValue("enable-oslogin"); val.Type() == cty.Bool {
				instance.OSLoginEnabled = types.BoolExplicit(val.True(), metadataAttr.Metadata())
			}
			if val := metadataAttr.MapValue("block-project-ssh-keys"); val.Type() == cty.Bool {
				instance.EnableProjectSSHKeyBlocking = types.BoolExplicit(val.True(), metadataAttr.Metadata())
			}
			if val := metadataAttr.MapValue("serial-port-enable"); val.Type() == cty.Bool {
				instance.EnableSerialPort = types.BoolExplicit(val.True(), metadataAttr.Metadata())
			}
		}

		// disks
		for _, diskBlock := range instanceBlock.GetBlocks("boot_disk") {
			disk := compute.Disk{
				Metadata: diskBlock.Metadata(),
				Name:     types.StringDefault("", diskBlock.Metadata()),
				Encryption: compute.DiskEncryption{
					Metadata:   diskBlock.Metadata(),
					RawKey:     diskBlock.GetAttribute("disk_encryption_key_raw").AsBytesValueOrDefault(nil, diskBlock),
					KMSKeyLink: diskBlock.GetAttribute("kms_key_self_link").AsStringValueOrDefault("", diskBlock),
				},
			}
			instance.BootDisks = append(instance.BootDisks, disk)
		}
		for _, diskBlock := range instanceBlock.GetBlocks("attached_disk") {
			disk := compute.Disk{
				Metadata: diskBlock.Metadata(),
				Name:     types.StringDefault("", diskBlock.Metadata()),
				Encryption: compute.DiskEncryption{
					Metadata:   diskBlock.Metadata(),
					RawKey:     diskBlock.GetAttribute("disk_encryption_key_raw").AsBytesValueOrDefault(nil, diskBlock),
					KMSKeyLink: diskBlock.GetAttribute("kms_key_self_link").AsStringValueOrDefault("", diskBlock),
				},
			}
			instance.AttachedDisks = append(instance.AttachedDisks, disk)
		}

		instances = append(instances, instance)
	}

	return instances
}
