package appservice

import "github.com/aquasecurity/defsec/types"

type AppService struct {
	types.Metadata
	Services     []Service
	FunctionApps []FunctionApp
}

type Service struct {
	types.Metadata
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
	types.Metadata
	HTTPSOnly types.BoolValue
}


func (a *AppService) GetMetadata() *types.Metadata {
	return &a.Metadata
}

func (a *AppService) GetRawValue() interface{} {
	return nil
}    


func (s *Service) GetMetadata() *types.Metadata {
	return &s.Metadata
}

func (s *Service) GetRawValue() interface{} {
	return nil
}    


func (f *FunctionApp) GetMetadata() *types.Metadata {
	return &f.Metadata
}

func (f *FunctionApp) GetRawValue() interface{} {
	return nil
}    
