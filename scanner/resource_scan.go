package scanner

type checkFunc func(resource Resource) *Result

var resourceChecks = map[string][]checkFunc{
	"aws_security_group_rule":        []checkFunc{checkAWSOpenSecurityGroupRules},
	"aws_security_group":             []checkFunc{checkAWSOpenSecurityGroup},
	"aws_db_security_group":          []checkFunc{checkAWSEC2ClassicUsage},
	"aws_redshift_security_group":    []checkFunc{checkAWSEC2ClassicUsage},
	"aws_elasticache_security_group": []checkFunc{checkAWSEC2ClassicUsage},
	"aws_alb":                        []checkFunc{checkAWSInternal},
	"aws_lb":                         []checkFunc{checkAWSInternal},
	"aws_elb":                        []checkFunc{checkAWSInternal},
	"aws_db_instance":                []checkFunc{checkAWSNotPublic},
	"aws_dms_replication_instance":   []checkFunc{checkAWSNotPublic},
	"aws_rds_cluster_instance":       []checkFunc{checkAWSNotPublic},
	"aws_redshift_cluster":           []checkFunc{checkAWSNotPublic},
	"aws_instance":                   []checkFunc{checkAWSHasNoPublicIP},
	"aws_launch_configuration":       []checkFunc{checkAWSHasNoPublicIP, checkAWSUnencryptedBlockDevices},
	"aws_s3_bucket":                  []checkFunc{checkAWSACL},
	"aws_lb_listener":                []checkFunc{checkAWSNotUsingHTTP, checkAWSNotUsingPort80},
	"aws_alb_listener":               []checkFunc{checkAWSOutdatedSSLPolicy},
}

func scanResource(resource Resource) []Result {

	results := []Result{}

	if resource.Ignored() {
		return results
	}

	if checks, ok := resourceChecks[resource.Type]; ok {
		for _, check := range checks {
			if result := check(resource); result != nil {
				results = append(results, *result)
			}
		}
	}

	return results
}
