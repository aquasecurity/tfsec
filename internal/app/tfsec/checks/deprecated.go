package checks

/*
// TODO replace this
var configuredChecks = map[string]map[string][]checkFunc{
	"resource": {
		"aws_lb_listener":              {checkAWSOutdatedSSLPolicy, checkAWSNotUsingHTTP, checkAWSNotUsingPort80},
		"aws_alb_listener":             {checkAWSOutdatedSSLPolicy, checkAWSNotUsingHTTP, checkAWSNotUsingPort80},
	},
}
*/

/*
func checkAWSNotUsingPort80(*hcl.Block, *hcl.EvalContext) *models.Result {
	if port, err := resource.Get("port"); err == nil {
		if port.String() == "80" {
			return scanner.NewResult(
				port.pos,
				fmt.Sprintf("Resource '%s' uses port 80 instead of 443.", resource.String()),
			)
		}
	}
	return nil
}

func checkAWSNotUsingHTTP(*hcl.Block, *hcl.EvalContext) *models.Result {
	if protocol, err := resource.Get("protocol"); err == nil {
		if strings.ToUpper(protocol.String()) == "HTTP" {
			return scanner.NewResult(
				protocol.pos,
				fmt.Sprintf("Resource '%s' uses plain HTTP instead of HTTPS.", resource.String()),
			)
		}
	} else if err != scanner.ErrIgnored {
		return scanner.NewResult(
			resource.pos,
			fmt.Sprintf("Resource '%s' has no protocol defined, which results in plain HTTP being used.", resource.String()),
		)
	}
	return nil
}

*/
