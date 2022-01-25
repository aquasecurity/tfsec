package cloudfront

import "github.com/aquasecurity/defsec/types"

type Cloudfront struct {
	types.Metadata
	Distributions []Distribution
}

type Distribution struct {
	types.Metadata
	WAFID                  types.StringValue
	Logging                Logging
	DefaultCacheBehaviour  CacheBehaviour
	OrdererCacheBehaviours []CacheBehaviour
	ViewerCertificate      ViewerCertificate
}

type Logging struct {
	types.Metadata
	Bucket types.StringValue
}

type CacheBehaviour struct {
	types.Metadata
	ViewerProtocolPolicy types.StringValue
}

const (
	ViewerPolicyProtocolAllowAll        = "allow-all"
	ViewerPolicyProtocolHTTPSOnly       = "https-only"
	ViewerPolicyProtocolRedirectToHTTPS = "redirect-to-https"
)

const (
	ProtocolVersionTLS1_2 = "TLSv1.2_2021"
)

type ViewerCertificate struct {
	types.Metadata
	MinimumProtocolVersion types.StringValue
}

func (d *Distribution) GetMetadata() *types.Metadata {
	return &d.Metadata
}

func (d *Distribution) GetRawValue() interface{} {
	return nil
}

func (c *CacheBehaviour) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *CacheBehaviour) GetRawValue() interface{} {
	return nil
}

func (c *Cloudfront) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Cloudfront) GetRawValue() interface{} {
	return nil
}

func (l *Logging) GetMetadata() *types.Metadata {
	return &l.Metadata
}

func (l *Logging) GetRawValue() interface{} {
	return nil
}

func (v *ViewerCertificate) GetMetadata() *types.Metadata {
	return &v.Metadata
}

func (v *ViewerCertificate) GetRawValue() interface{} {
	return nil
}
