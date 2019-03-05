package scanner

import (
	"fmt"
	"strings"
)

func checkAWSEC2ClassicUsage(resource Resource) *Result {
	return NewResult(
		resource.pos,
		fmt.Sprintf("Resource '%s' uses EC2 Classic. Use a VPC instead.", resource.String()),
	)
}

func checkAWSUnencryptedBlockDevices(resource Resource) *Result {

	if bd, err := resource.Get("ebs_block_device"); err == nil {
		if enc, err := bd.Get("encrypted"); strings.ToLower(enc.String()) == "false" || strings.ToLower(enc.String()) == "0" {
			return NewResult(
				enc.pos,
				fmt.Sprintf("Resource '%s' uses an unencrypted EBS block device.", resource.String()),
			)
		} else if err != nil {
			return NewResult(
				bd.pos,
				fmt.Sprintf("Resource '%s' uses an unencrypted EBS block device.", resource.String()),
			)
		}
	}

	return nil
}

func checkAWSOutdatedSSLPolicy(resource Resource) *Result {

	oldPolicies := []string{
		"ELBSecurityPolicy-2015-05",
		"ELBSecurityPolicy-TLS-1-0-2015-04",
		"ELBSecurityPolicy-2016-08",
		"ELBSecurityPolicy-TLS-1-1-2017-01",
	}

	if policy, err := resource.Get("ssl_policy"); err == nil {
		p := policy.String()
		for _, old := range oldPolicies {
			if old == p {
				return NewResult(
					policy.pos,
					fmt.Sprintf("Resource '%s' is using an outdated SSL policy.", resource.String()),
				)
			}
		}
	}
	return nil
}

func checkAWSInternal(resource Resource) *Result {
	if internal, err := resource.Get("internal"); err == nil {
		if strings.ToLower(internal.String()) == "false" || strings.ToLower(internal.String()) == "0" {
			return NewResult(
				internal.pos,
				fmt.Sprintf("Resource '%s' is exposed externally.", resource.String()),
			)
		}
	}
	return nil
}

func checkAWSNotUsingPort80(resource Resource) *Result {
	if port, err := resource.Get("port"); err == nil {
		if port.String() == "80" {
			return NewResult(
				port.pos,
				fmt.Sprintf("Resource '%s' uses port 80 instead of 443.", resource.String()),
			)
		}
	}
	return nil
}

func checkAWSNotUsingHTTP(resource Resource) *Result {
	if protocol, err := resource.Get("protocol"); err == nil {
		if strings.ToUpper(protocol.String()) == "HTTP" {
			return NewResult(
				protocol.pos,
				fmt.Sprintf("Resource '%s' uses plain HTTP instead of HTTPS.", resource.String()),
			)
		}
	} else if err != ErrIgnored {
		return NewResult(
			resource.pos,
			fmt.Sprintf("Resource '%s' has no protocol defined, which results in plain HTTP being used.", resource.String()),
		)
	}
	return nil
}

func checkAWSACL(resource Resource) *Result {
	if acl, err := resource.Get("acl"); err == nil {
		if acl.String() == "public-read" || acl.String() == "public-read-write" || acl.String() == "website" {
			return NewResult(
				acl.pos,
				fmt.Sprintf("Resource '%s' has an ACL which allows public read access.", resource.String()),
			)
		}
	}
	return nil
}

func checkAWSHasNoPublicIP(resource Resource) *Result {
	if public, err := resource.Get("associate_public_ip_address"); err == nil {
		if strings.ToLower(public.String()) == "true" || strings.ToLower(public.String()) == "1" {
			return NewResult(
				public.pos,
				fmt.Sprintf("Resource '%s' has a public IP address associated.", resource.String()),
			)
		}
	}
	return nil
}

func checkAWSNotPublic(resource Resource) *Result {
	if public, err := resource.Get("publicly_accessible"); err == nil {
		if strings.ToLower(public.String()) == "true" || strings.ToLower(public.String()) == "1" {
			return NewResult(
				public.pos,
				fmt.Sprintf("Resource '%s' allows public access.", resource.String()),
			)
		}
	}
	return nil
}

// ensure no rules allow inbound traffic from 0.0.0.0/0
func checkAWSOpenSecurityGroup(resource Resource) *Result {

	if ingress, err := resource.Get("ingress"); err == nil {
		if blocks, err := ingress.Get("cidr_blocks"); err == nil {
			for _, block := range blocks.StringList() {
				if strings.HasSuffix(block, "/0") {
					return NewResult(
						blocks.pos,
						fmt.Sprintf("Resource '%s' defines a fully open inbound security group rule.", resource.String()),
					)
				}
			}

		}
	}

	return nil
}

// ensure no rules allow inbound traffic from 0.0.0.0/0
func checkAWSOpenSecurityGroupRules(resource Resource) *Result {

	if typ, err := resource.Get("type"); err == nil && typ.String() == "ingress" {
		if blocks, err := resource.Get("cidr_blocks"); err == nil {
			for _, block := range blocks.StringList() {
				if strings.HasSuffix(block, "/0") {
					return NewResult(
						blocks.pos,
						fmt.Sprintf("Resource '%s' defines a fully open inbound security group rule.", resource.String()),
					)
				}
			}

		}
	}

	return nil
}
