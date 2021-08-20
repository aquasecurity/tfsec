package s3

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter/testutils"
	"github.com/stretchr/testify/assert"
)

func Test_PubcliAccessBlock(t *testing.T) {
	testCases := []struct {
		desc                       string
		source                     string
		expectedBuckets            int
		expectedPublicAccessBlocks int
	}{
		{
			desc: "public access block is found when using the bucket name as the lookup",
			source: `
resource "aws_s3_bucket" "example" {
	name = "bucketname"
}

resource "aws_s3_bucket_public_access_block" "example_access_block"{
	bucket = "bucketname"
}
`,
			expectedBuckets:            1,
			expectedPublicAccessBlocks: 1,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {

			modules := testutils.CreateModulesFromSource(tC.source, ".tf", t)
			s3Ctx := Adapt(modules)

			assert.Equal(t, tC.expectedBuckets, len(s3Ctx.Buckets))
			assert.Equal(t, tC.expectedPublicAccessBlocks, len(s3Ctx.PublicAccessBlocks))

			bucket := s3Ctx.Buckets[0]
			assert.NotNil(t, bucket.PublicAccessBlock)

			pubAccess := s3Ctx.PublicAccessBlocks[0]
			assert.Equal(t, bucket.Name.Value, pubAccess.Bucket.Name.Value)

			assert.NotNil(t, pubAccess.Bucket)

		})
	}

}
