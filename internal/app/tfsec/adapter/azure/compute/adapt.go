package compute

import (
	"encoding/base64"

	"github.com/aquasecurity/defsec/provider/azure/compute"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) compute.Compute {
	return adaptCompute(modules)
}

func adaptCompute(modules []block.Module) compute.Compute {

	var managedDisks []compute.ManagedDisk
	var linuxVirtualMachines []compute.LinuxVirtualMachine
	var windowsVirtualMachines []compute.WindowsVirtualMachine

	for _, module := range modules {

		for _, resource := range module.GetResourcesByType("azurerm_linux_virtual_machine") {
			linuxVirtualMachines = append(linuxVirtualMachines, adaptLinuxVM(resource))
		}
		for _, resource := range module.GetResourcesByType("azurerm_windows_virtual_machine") {
			windowsVirtualMachines = append(windowsVirtualMachines, adaptWindowsVM(resource))
		}
		for _, resource := range module.GetResourcesByType("azurerm_virtual_machine") {
			if resource.HasChild("os_profile_linux_config") {
				linuxVirtualMachines = append(linuxVirtualMachines, adaptLinuxVM(resource))
			} else if resource.HasChild("os_profile_windows_config") {
				windowsVirtualMachines = append(windowsVirtualMachines, adaptWindowsVM(resource))
			}
		}
		for _, resource := range module.GetResourcesByType("azurerm_managed_disk") {
			managedDisks = append(managedDisks, adaptManagedDisk(resource))
		}
	}

	return compute.Compute{
		LinuxVirtualMachines:   linuxVirtualMachines,
		WindowsVirtualMachines: windowsVirtualMachines,
		ManagedDisks:           managedDisks,
	}
}

func adaptManagedDisk(resource block.Block) compute.ManagedDisk {
	encryptionBlock := resource.GetBlock("encryption_settings")
	var enabledVal types.BoolValue

	if encryptionBlock.IsNotNil() {
		enabledAttr := encryptionBlock.GetAttribute("enabled")
		enabledVal = enabledAttr.AsBoolValueOrDefault(false, encryptionBlock)
	}

	return compute.ManagedDisk{
		Encryption: compute.Encryption{
			Enabled: enabledVal,
		},
	}
}

func adaptLinuxVM(resource block.Block) compute.LinuxVirtualMachine {
	workingBlock := resource

	if resource.TypeLabel() == "azurerm_virtual_machine" {
		if b := resource.GetBlock("os_profile"); b.IsNotNil() {
			workingBlock = b
		}
	}
	customDataAttr := workingBlock.GetAttribute("custom_data")
	customDataVal := types.StringDefault("", workingBlock.Metadata())
	if customDataAttr.IsResolvable() && customDataAttr.IsString() {
		encoded, err := base64.StdEncoding.DecodeString(customDataAttr.Value().AsString())
		if err != nil {
			encoded = []byte(customDataAttr.Value().AsString())
		}
		customDataVal = types.String(string(encoded), *workingBlock.GetMetadata())
	}

	if resource.TypeLabel() == "azurerm_virtual_machine" {
		workingBlock = resource.GetBlock("os_profile_linux_config")
	}
	disablePasswordAuthAttr := workingBlock.GetAttribute("disable_password_authentication")
	disablePasswordAuthVal := disablePasswordAuthAttr.AsBoolValueOrDefault(true, workingBlock)

	return compute.LinuxVirtualMachine{
		VirtualMachine: compute.VirtualMachine{
			CustomData: customDataVal,
		},
		OSProfileLinuxConfig: compute.OSProfileLinuxConfig{
			DisablePasswordAuthentication: disablePasswordAuthVal,
		},
	}
}

func adaptWindowsVM(resource block.Block) compute.WindowsVirtualMachine {
	workingBlock := resource

	if resource.TypeLabel() == "azurerm_virtual_machine" {
		if b := resource.GetBlock("os_profile"); b.IsNotNil() {
			workingBlock = b
		}
	}

	customDataAttr := workingBlock.GetAttribute("custom_data")
	customDataVal := types.StringDefault("", workingBlock.Metadata())

	if customDataAttr.IsResolvable() && customDataAttr.IsString() {
		encoded, err := base64.StdEncoding.DecodeString(customDataAttr.Value().AsString())
		if err != nil {
			encoded = []byte(customDataAttr.Value().AsString())
		}
		customDataVal = types.String(string(encoded), *workingBlock.GetMetadata())
	}

	return compute.WindowsVirtualMachine{
		VirtualMachine: compute.VirtualMachine{
			CustomData: customDataVal,
		},
	}
}
