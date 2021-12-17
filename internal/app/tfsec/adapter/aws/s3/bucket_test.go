package s3

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/testutils"
	"github.com/stretchr/testify/assert"
)

func Test_GetBuckets(t *testing.T) {

	source := `
resource "aws_s3_bucket" "bucket1" {

	
}
`
	modules := testutils.CreateModulesFromSource(source, ".tf", t)

	s3 := Adapt(modules)

	assert.Equal(t, 1, len(s3.Buckets))

}
