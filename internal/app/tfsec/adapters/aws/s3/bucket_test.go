package s3

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
	"github.com/stretchr/testify/assert"
)

func Test_GetBuckets(t *testing.T) {

	source := `
resource "aws_s3_bucket" "bucket1" {

	
}
`
	modules := testutil.CreateModulesFromSource(source, ".tf", t)

	adapter := Adapter{
		modules: modules,
	}

	buckets := adapter.GetBuckets()

	assert.Equal(t, 1, len(buckets))

}
