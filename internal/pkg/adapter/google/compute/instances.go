package compute

import (
	"github.com/aquasecurity/defsec/provider/google/compute"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
	"github.com/zclconf/go-cty/cty"
)

func adaptInstances(modules block.Modules) (instances []compute.Instance) {

	for _, instanceBlock := range modules.GetResourcesByType("google_compute_instance") {
		var instance compute.Instance
		instance.Metadata = instanceBlock.Metadata()

		// network interfaces
		for _, networkInterfaceBlock := range instanceBlock.GetBlocks("network_interface") {
			var ni compute.NetworkInterface
			ni.HasPublicIP = types.BoolDefault(false, networkInterfaceBlock.Metadata())
			if accessConfigBlock := networkInterfaceBlock.GetBlock("access_config"); accessConfigBlock.IsNotNil() {
				ni.HasPublicIP = types.Bool(true, accessConfigBlock.Metadata())
			}
			instance.NetworkInterfaces = append(instance.NetworkInterfaces, ni)
		}

		// vm shielding
		if shieldedBlock := instanceBlock.GetBlock("shielded_instance_config"); shieldedBlock.IsNotNil() {
			instance.ShieldedVM.IntegrityMonitoringEnabled = shieldedBlock.GetAttribute("enable_integrity_monitoring").AsBoolValueOrDefault(true, shieldedBlock)
			instance.ShieldedVM.VTPMEnabled = shieldedBlock.GetAttribute("enable_vtpm").AsBoolValueOrDefault(true, shieldedBlock)
			instance.ShieldedVM.SecureBootEnabled = shieldedBlock.GetAttribute("enable_secure_boot").AsBoolValueOrDefault(false, shieldedBlock)
		} else {
			instance.ShieldedVM.IntegrityMonitoringEnabled = types.BoolDefault(false, instanceBlock.Metadata())
			instance.ShieldedVM.VTPMEnabled = types.BoolDefault(false, instanceBlock.Metadata())
			instance.ShieldedVM.SecureBootEnabled = types.BoolDefault(false, instanceBlock.Metadata())
		}

		if serviceAccountBlock := instanceBlock.GetBlock("service_account"); serviceAccountBlock.IsNotNil() {
			instance.ServiceAccount.Email = serviceAccountBlock.GetAttribute("email").AsStringValueOrDefault("", serviceAccountBlock)
		} else {
			instance.ServiceAccount.Email = types.StringDefault("", instanceBlock.Metadata())
		}

		instance.CanIPForward = instanceBlock.GetAttribute("can_ip_forward").AsBoolValueOrDefault(false, instanceBlock)

		// metadata
		instance.OSLoginEnabled = types.BoolDefault(true, instanceBlock.Metadata())
		instance.EnableProjectSSHKeyBlocking = types.BoolDefault(false, instanceBlock.Metadata())
		instance.EnableSerialPort = types.BoolDefault(false, instanceBlock.Metadata())
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
			var disk compute.Disk
			disk.Encryption.RawKey = diskBlock.GetAttribute("disk_encryption_key_raw").
				AsBytesValueOrDefault(nil, diskBlock)
			disk.Encryption.KMSKeyLink = diskBlock.GetAttribute("kms_key_self_link").
				AsStringValueOrDefault("", diskBlock)
			instance.BootDisks = append(instance.BootDisks, disk)
		}
		for _, diskBlock := range instanceBlock.GetBlocks("attached_disk") {
			var disk compute.Disk
			disk.Encryption.RawKey = diskBlock.GetAttribute("disk_encryption_key_raw").
				AsBytesValueOrDefault(nil, diskBlock)
			disk.Encryption.KMSKeyLink = diskBlock.GetAttribute("kms_key_self_link").
				AsStringValueOrDefault("", diskBlock)
			instance.AttachedDisks = append(instance.AttachedDisks, disk)
		}

		instances = append(instances, instance)
	}

	return instances
}
