package compute

import (
	"github.com/aquasecurity/defsec/provider/google/compute"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func adaptDisks(modules block.Modules) (disks []compute.Disk) {

	for _, diskBlock := range modules.GetResourcesByType("google_compute_disk") {
		var disk compute.Disk
		disk.Metadata = diskBlock.Metadata()
		if encBlock := diskBlock.GetBlock("disk_encryption_key"); encBlock.IsNotNil() {
			disk.Encryption.KMSKeyLink = encBlock.GetAttribute("kms_key_self_link").AsStringValueOrDefault("", encBlock)
			disk.Encryption.RawKey = encBlock.GetAttribute("raw_key").AsBytesValueOrDefault(nil, encBlock)
		} else {
			disk.Encryption.KMSKeyLink = types.StringDefault("", diskBlock.Metadata())
			disk.Encryption.RawKey = types.BytesDefault(nil, diskBlock.Metadata())
		}
		disks = append(disks, disk)
	}

	return disks
}
