package cloudfront

import "github.com/aquasecurity/defsec/types"

type Cloudfront struct {
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
