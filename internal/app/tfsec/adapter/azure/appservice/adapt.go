package appservice

import (
	"github.com/aquasecurity/defsec/provider/azure/appservice"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules block.Modules) appservice.AppService {
	return appservice.AppService{
		Services:     adaptServices(modules),
		FunctionApps: adaptFunctionApps(modules),
	}
}

func adaptServices(modules block.Modules) []appservice.Service {
	var services []appservice.Service

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_app_service") {
			services = append(services, adaptService(resource))
		}
	}
	return services
}

func adaptFunctionApps(modules block.Modules) []appservice.FunctionApp {
	var functionApps []appservice.FunctionApp

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_function_app") {
			functionApps = append(functionApps, adaptFunctionApp(resource))
		}
	}
	return functionApps
}

func adaptService(resource *block.Block) appservice.Service {
	enableClientCertAttr := resource.GetAttribute("client_cert_enabled")
	enableClientCertVal := enableClientCertAttr.AsBoolValueOrDefault(false, resource)

	identityBlock := resource.GetBlock("identity")
	typeVal := types.String("", *resource.GetMetadata())
	if identityBlock.IsNotNil() {
		typeAttr := identityBlock.GetAttribute("type")
		typeVal = typeAttr.AsStringValueOrDefault("", identityBlock)
	}

	authBlock := resource.GetBlock("auth_settings")
	enabledVal := types.Bool(false, *resource.GetMetadata())
	if authBlock.IsNotNil() {
		enabledAttr := authBlock.GetAttribute("enabled")
		enabledVal = enabledAttr.AsBoolValueOrDefault(false, authBlock)
	}

	siteBlock := resource.GetBlock("site_config")
	enableHTTP2Val := types.Bool(false, *resource.GetMetadata())
	minTLSVersionVal := types.String("1.2", *resource.GetMetadata())
	if siteBlock.IsNotNil() {
		enableHTTP2Attr := siteBlock.GetAttribute("http2_enabled")
		enableHTTP2Val = enableHTTP2Attr.AsBoolValueOrDefault(false, siteBlock)

		minTLSVersionAttr := siteBlock.GetAttribute("min_tls_version")
		minTLSVersionVal = minTLSVersionAttr.AsStringValueOrDefault("1.2", siteBlock)
	}

	return appservice.Service{
		EnableClientCert: enableClientCertVal,
		Identity: struct{ Type types.StringValue }{
			Type: typeVal,
		},
		Authentication: struct{ Enabled types.BoolValue }{
			Enabled: enabledVal,
		},
		Site: struct {
			EnableHTTP2       types.BoolValue
			MinimumTLSVersion types.StringValue
		}{
			EnableHTTP2:       enableHTTP2Val,
			MinimumTLSVersion: minTLSVersionVal,
		},
	}
}

func adaptFunctionApp(resource *block.Block) appservice.FunctionApp {
	HTTPSOnlyAttr := resource.GetAttribute("https_only")
	HTTPSOnlyVal := HTTPSOnlyAttr.AsBoolValueOrDefault(false, resource)

	return appservice.FunctionApp{
		HTTPSOnly: HTTPSOnlyVal,
	}
}
