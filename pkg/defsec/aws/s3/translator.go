package s3

type S3Adapter interface {
	GetBuckets() []Bucket
	GetPublicAccessBlock() []PublicAccessBlock
}
