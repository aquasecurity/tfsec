package appservice

import "github.com/aquasecurity/defsec/types"

type AppService struct {
	Services     []Service
	FunctionApps []FunctionApp
}

type Service struct {
	EnableClientCert types.BoolValue
	Identity         struct {
		Type types.StringValue
	}
	Authentication struct {
		Enabled types.BoolValue
	}
	Site struct {
		EnableHTTP2       types.BoolValue
		MinimumTLSVersion types.StringValue
	}
}

type FunctionApp struct {
	HTTPSOnly types.BoolValue
}
