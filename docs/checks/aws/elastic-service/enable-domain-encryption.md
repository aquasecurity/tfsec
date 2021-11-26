---
title: enable-domain-encryption
---

### Explanation


You should ensure your Elasticsearch data is encrypted at rest to help prevent sensitive information from being read by unauthorised users. 


### Possible Impact
Data will be readable if compromised

### Suggested Resolution
Enable ElasticSearch domain encryption


### Insecure Example

The following example will fail the aws-elastic-service-enable-domain-encryption check.

```terraform

resource "aws_elasticsearch_domain" "bad_example" {
  domain_name = "domain-foo"

  encrypt_at_rest {
    enabled = false
  }
}

```



### Secure Example

The following example will pass the aws-elastic-service-enable-domain-encryption check.

```terraform

resource "aws_elasticsearch_domain" "good_example" {
  domain_name = "domain-foo"

  encrypt_at_rest {
    enabled = true
  }
}

```




### Related Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#encrypt_at_rest](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#encrypt_at_rest){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/encryption-at-rest.html](https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/encryption-at-rest.html){:target="_blank" rel="nofollow noreferrer noopener"}


