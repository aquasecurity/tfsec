---
title: ec2
---

# ec2

## Checks


- [add-description-to-security-group](add-description-to-security-group) Missing description for security group.

- [add-description-to-security-group-rule](add-description-to-security-group-rule) Missing description for security group rule.

- [enable-at-rest-encryption](enable-at-rest-encryption) Instance with unencrypted block device.

- [enable-launch-config-at-rest-encryption](enable-launch-config-at-rest-encryption) Launch configuration with unencrypted block device.

- [enable-volume-encryption](enable-volume-encryption) EBS volumes must be encrypted

- [enforce-http-token-imds](enforce-http-token-imds) aws_instance should activate session tokens for Instance Metadata Service.

- [enforce-launch-config-http-token-imds](enforce-launch-config-http-token-imds) aws_instance should activate session tokens for Instance Metadata Service.

- [no-default-vpc](no-default-vpc) AWS best practice to not use the default VPC for workflows

- [no-excessive-port-access](no-excessive-port-access) An ingress Network ACL rule allows ALL ports.

- [no-public-egress-sgr](no-public-egress-sgr) An egress security group rule allows traffic to /0.

- [no-public-ingress-acl](no-public-ingress-acl) An ingress Network ACL rule allows specific ports from /0.

- [no-public-ingress-sgr](no-public-ingress-sgr) An ingress security group rule allows traffic from /0.

- [no-public-ip](no-public-ip) Launch configuration should not have a public IP address.

- [no-public-ip-subnet](no-public-ip-subnet) Instances in a subnet should not receive a public IP address by default.

- [no-secrets-in-launch-template-user-data](no-secrets-in-launch-template-user-data) User data for EC2 instances must not contain sensitive AWS keys

- [no-secrets-in-user-data](no-secrets-in-user-data) User data for EC2 instances must not contain sensitive AWS keys

- [no-sensitive-info](no-sensitive-info) Ensure all data stored in the launch configuration EBS is securely encrypted

- [volume-encryption-customer-key](volume-encryption-customer-key) EBS volume encryption should use Customer Managed Keys



