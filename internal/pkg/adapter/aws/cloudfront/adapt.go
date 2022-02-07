package cloudfront

import (
	"github.com/aquasecurity/defsec/provider/aws/cloudfront"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) cloudfront.Cloudfront {
	return cloudfront.Cloudfront{
		Distributions: adaptDistributions(modules),
	}
}

func adaptDistributions(modules block.Modules) []cloudfront.Distribution {
	var distributions []cloudfront.Distribution
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_cloudfront_distribution") {
			distributions = append(distributions, adaptDistribution(resource))
		}
	}
	return distributions
}

func adaptDistribution(resource *block.Block) cloudfront.Distribution {

	distribution := cloudfront.Distribution{
		Metadata: resource.Metadata(),
		WAFID:    types.StringDefault("", resource.Metadata()),
		Logging: cloudfront.Logging{
			Metadata: resource.Metadata(),
			Bucket:   types.StringDefault("", resource.Metadata()),
		},
		DefaultCacheBehaviour: cloudfront.CacheBehaviour{
			Metadata:             resource.Metadata(),
			ViewerProtocolPolicy: types.String("allow-all", resource.Metadata()),
		},
		ViewerCertificate: cloudfront.ViewerCertificate{
			Metadata:               resource.Metadata(),
			MinimumProtocolVersion: types.StringDefault("TLSv1", resource.Metadata()),
		},
	}

	distribution.WAFID = resource.GetAttribute("web_acl_id").AsStringValueOrDefault("", resource)

	if loggingBlock := resource.GetBlock("logging_config"); loggingBlock.IsNotNil() {
		distribution.Logging.Metadata = loggingBlock.Metadata()
		bucketAttr := loggingBlock.GetAttribute("bucket")
		distribution.Logging.Bucket = bucketAttr.AsStringValueOrDefault("", loggingBlock)
	}

	if defaultCacheBlock := resource.GetBlock("default_cache_behavior"); defaultCacheBlock.IsNotNil() {
		distribution.DefaultCacheBehaviour.Metadata = defaultCacheBlock.Metadata()
		viewerProtocolPolicyAttr := defaultCacheBlock.GetAttribute("viewer_protocol_policy")
		distribution.DefaultCacheBehaviour.ViewerProtocolPolicy = viewerProtocolPolicyAttr.AsStringValueOrDefault("allow-all", defaultCacheBlock)
	}

	orderedCacheBlocks := resource.GetBlocks("ordered_cache_behavior")
	for _, orderedCacheBlock := range orderedCacheBlocks {
		ViewerProtocolPolicyAttr := orderedCacheBlock.GetAttribute("viewer_protocol_policy")
		ViewerProtocolPolicyVal := ViewerProtocolPolicyAttr.AsStringValueOrDefault("allow-all", orderedCacheBlock)
		distribution.OrdererCacheBehaviours = append(distribution.OrdererCacheBehaviours, cloudfront.CacheBehaviour{
			Metadata:             orderedCacheBlock.Metadata(),
			ViewerProtocolPolicy: ViewerProtocolPolicyVal,
		})
	}

	if viewerCertBlock := resource.GetBlock("viewer_certificate"); viewerCertBlock.IsNotNil() {
		distribution.ViewerCertificate.Metadata = viewerCertBlock.Metadata()
		minProtocolAttr := viewerCertBlock.GetAttribute("minimum_protocol_version")
		distribution.ViewerCertificate.MinimumProtocolVersion = minProtocolAttr.AsStringValueOrDefault("TLSv1", viewerCertBlock)
	}

	return distribution
}
