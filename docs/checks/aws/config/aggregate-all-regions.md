---
title: Config configuration aggregator should be using all regions for source
---

# Config configuration aggregator should be using all regions for source

### Default Severity: <span class="severity high">high</span>

### Explanation

The configuration aggregator should be configured with all_regions for the source. 

This will help limit the risk of any unmonitored configuration in regions that are thought to be unused.

### Possible Impact
Sources that aren't covered by the aggregator are not include in the configuration

### Suggested Resolution
Set the aggregator to cover all regions


### Insecure Example

The following example will fail the aws-config-aggregate-all-regions check.
```terraform

 resource "aws_config_configuration_aggregator" "bad_example" {
 	name = "example"
 	  
 	account_aggregation_source {
 	  account_ids = ["123456789012"]
 	  regions     = ["us-west-2", "eu-west-1"]
 	}
 }
 
```



### Secure Example

The following example will pass the aws-config-aggregate-all-regions check.
```terraform

 resource "aws_config_configuration_aggregator" "good_example" {
 	name = "example"
 	  
 	account_aggregation_source {
 	  account_ids = ["123456789012"]
 	  all_regions = true
 	}
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/config_configuration_aggregator#all_regions](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/config_configuration_aggregator#all_regions){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/config/latest/developerguide/aggregate-data.html](https://docs.aws.amazon.com/config/latest/developerguide/aggregate-data.html){:target="_blank" rel="nofollow noreferrer noopener"}



