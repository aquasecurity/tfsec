package checks

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/liamg/tfsec/internal/app/tfsec/models"
)

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_s3_bucket"},
		CheckFunc: func(block *hcl.Block, ctx *hcl.EvalContext) *models.Result {
			if val, attrRange, exists := getAttribute(block, ctx, "acl"); exists {
				acl := val.AsString()
				if acl == "public-read" || acl == "public-read-write" || acl == "website" {
					return &models.Result{
						Range:       attrRange,
						Description: fmt.Sprintf("Resource '%s' has an ACL which allows public read access.", getBlockName(block)),
					}
				}
			}
			return nil
		},
	})
}
