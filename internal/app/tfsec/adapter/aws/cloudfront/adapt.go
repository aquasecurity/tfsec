package cloudfront

import (
	"github.com/aquasecurity/defsec/provider/aws/cloudfront"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) cloudfront.Cloudfront {
	return cloudfront.Cloudfront{
		Distributions: adaptDistributions(modules),
	}
}

func adaptDistributions(modules []block.Module) []cloudfront.Distribution {
	var distributions []cloudfront.Distribution
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_cloudfront_distribution") {
			distributions = append(distributions, adaptDistribution(resource))
		}
	}
	return distributions
}

func adaptDistribution(resource block.Block) cloudfront.Distribution {
	WAFIDAtrr := resource.GetAttribute("web_acl_id")
	WAFIDAVal := WAFIDAtrr.AsStringValueOrDefault("", resource)

	defaultCacheBehaviour := cloudfront.CacheBehaviour{
		Metadata:             *resource.GetMetadata(),
		ViewerProtocolPolicy: types.String("allow-all", *resource.GetMetadata()),
	}
	var orderedCacheBehaviours []cloudfront.CacheBehaviour

	bucketVal := types.String("", *resource.GetMetadata())
	if resource.HasChild("logging_config") {
		loggingBlock := resource.GetBlock("logging_config")
		bucketAttr := loggingBlock.GetAttribute("bucket")
		bucketVal = bucketAttr.AsStringValueOrDefault("", loggingBlock)
	}

	if resource.HasChild("default_cache_behavior") {
		defaultCacheBlock := resource.GetBlock("default_cache_behavior")
		defaultCacheBehaviour.Metadata = *defaultCacheBlock.GetMetadata()
		ViewerProtocolPolicyAttr := defaultCacheBlock.GetAttribute("viewer_protocol_policy")
		defaultCacheBehaviour.ViewerProtocolPolicy = ViewerProtocolPolicyAttr.AsStringValueOrDefault("allow-all", defaultCacheBlock)
	}

	orderedCacheBlocks := resource.GetBlocks("ordered_cache_behavior")
	for _, orderedCacheBlock := range orderedCacheBlocks {
		ViewerProtocolPolicyAttr := orderedCacheBlock.GetAttribute("viewer_protocol_policy")
		ViewerProtocolPolicyVal := ViewerProtocolPolicyAttr.AsStringValueOrDefault("allow-all", orderedCacheBlock)

		orderedCacheBehaviours = append(orderedCacheBehaviours, cloudfront.CacheBehaviour{
			Metadata:             *orderedCacheBlock.GetMetadata(),
			ViewerProtocolPolicy: ViewerProtocolPolicyVal,
		})
	}

	minProtocolVal := types.String("", *resource.GetMetadata())
	if resource.HasChild("viewer_certificate") {
		viewerCertBlock := resource.GetBlock("viewer_certificate")
		minProtocolAttr := viewerCertBlock.GetAttribute("minimum_protocol_version")
		minProtocolVal = minProtocolAttr.AsStringValueOrDefault("TLSv1", viewerCertBlock)
	}

	return cloudfront.Distribution{
		Metadata: *resource.GetMetadata(),
		WAFID:    WAFIDAVal,
		Logging: cloudfront.Logging{
			Bucket: bucketVal,
		},
		DefaultCacheBehaviour:  defaultCacheBehaviour,
		OrdererCacheBehaviours: orderedCacheBehaviours,
		ViewerCertificate: cloudfront.ViewerCertificate{
			MinimumProtocolVersion: minProtocolVal,
		},
	}
}
