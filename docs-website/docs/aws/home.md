---
title: AWS Checks
permalink: /docs/aws/home/
has_children: true
has_toc: false
---

The included AWS checks are listed below. For more information about each check, see the link provided.

| Code  | Summary |
|:-------|:-------------|
|[AWS001](/docs/aws/AWS001)|S3 Bucket has an ACL defined which allows public access.|
|[AWS002](/docs/aws/AWS002)|S3 Bucket does not have logging enabled.|
|[AWS003](/docs/aws/AWS003)|AWS Classic resource usage.|
|[AWS004](/docs/aws/AWS004)|Use of plain HTTP.|
|[AWS005](/docs/aws/AWS005)|Load balancer is exposed to the internet.|
|[AWS006](/docs/aws/AWS006)|An ingress security group rule allows traffic from `/0`.|
|[AWS007](/docs/aws/AWS007)|An egress security group rule allows traffic to `/0`.|
|[AWS008](/docs/aws/AWS008)|An inline ingress security group rule allows traffic from `/0`.|
|[AWS009](/docs/aws/AWS009)|An inline egress security group rule allows traffic to `/0`.|
|[AWS010](/docs/aws/AWS010)|An outdated SSL policy is in use by a load balancer.|
|[AWS011](/docs/aws/AWS011)|A resource is marked as publicly accessible.|
|[AWS012](/docs/aws/AWS012)|A resource has a public IP address.|
|[AWS013](/docs/aws/AWS013)|Task definition defines sensitive environment variable(s).|
|[AWS014](/docs/aws/AWS014)|Launch configuration with unencrypted block device.|
|[AWS015](/docs/aws/AWS015)|Unencrypted SQS queue.|
|[AWS016](/docs/aws/AWS016)|Unencrypted SNS topic.|
|[AWS017](/docs/aws/AWS017)|Unencrypted S3 bucket.|
|[AWS018](/docs/aws/AWS018)|Missing description for security group/security group rule.|
|[AWS019](/docs/aws/AWS019)|A KMS key is not configured to auto-rotate.|
|[AWS020](/docs/aws/AWS020)|CloudFront distribution allows unencrypted (HTTP) communications.|
|[AWS021](/docs/aws/AWS021)|CloudFront distribution uses outdated SSL/TLS protocols.|
|[AWS022](/docs/aws/AWS022)|A MSK cluster allows unencrypted data in transit.|
|[AWS023](/docs/aws/AWS023)|ECR repository has image scans disabled.|
|[AWS024](/docs/aws/AWS024)|Kinesis stream is unencrypted.|
|[AWS025](/docs/aws/AWS025)|API Gateway domain name uses outdated SSL/TLS protocols.|
|[AWS031](/docs/aws/AWS031)|Elasticsearch domain isn't encrypted at rest.|
|[AWS032](/docs/aws/AWS032)|Elasticsearch domain uses plaintext traffic for node to node communication.|
|[AWS033](/docs/aws/AWS033)|Elasticsearch doesn't enforce HTTPS traffic.|
|[AWS034](/docs/aws/AWS034)|Elasticsearch domain endpoint is using outdated TLS policy.|
|[AWS035](/docs/aws/AWS035)|Unencrypted Elasticache Replication Group.|
|[AWS036](/docs/aws/AWS036)|Elasticache Replication Group uses unencrypted traffic.|
|[AWS037](/docs/aws/AWS037)|IAM Password policy should prevent password reuse.|
|[AWS038](/docs/aws/AWS038)|IAM Password policy should have expiry less than or equal to 90 days.|
|[AWS039](/docs/aws/AWS039)|IAM Password policy should have minimum password length of 14 or more characters.|
|[AWS040](/docs/aws/AWS040)|IAM Password policy should have requirement for at least one symbol in the password.|
|[AWS041](/docs/aws/AWS041)|IAM Password policy should have requirement for at least one number in the password.|
|[AWS042](/docs/aws/AWS042)|IAM Password policy should have requirement for at least one lowercase character.|
|[AWS043](/docs/aws/AWS043)|IAM Password policy should have requirement for at least one uppercase character.|
|[AWS044](/docs/aws/AWS044)|AWS provider has access credentials specified.|
|[AWS045](/docs/aws/AWS045)|CloudFront distribution does not have a WAF in front.|
|[AWS046](/docs/aws/AWS046)|AWS IAM policy document has wildcard action statement.|
|[AWS047](/docs/aws/AWS047)|AWS SQS policy document has wildcard action statement.|
|[AWS048](/docs/aws/AWS048)|EFS Encryption has not been enabled|
|[AWS049](/docs/aws/AWS049)|An ingress Network ACL rule allows specific ports from `/0`.|
|[AWS050](/docs/aws/AWS050)|An ingress Network ACL rule allows ALL ports from `/0`.|
|[AWS051](/docs/aws/AWS051)|There is no encryption specified or encryption is disabled on the RDS Cluster.|
|[AWS052](/docs/aws/AWS052)|RDS encryption has not been enabled at a DB Instance level.|
|[AWS053](/docs/aws/AWS053)|Encryption for RDS Perfomance Insights should be enabled.|
|[AWS054](/docs/aws/AWS054)|ElasticSearch domains should enforce HTTPS|
|[AWS055](/docs/aws/AWS055)|ElasticSearch nodes should communicate with node to node encryption enabled.|
|[AWS057](/docs/aws/AWS057)|Domain logging should be enabled for Elastic Search domains|

