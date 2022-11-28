package custom.rego.rego.sauce

deny[res] {
    count(input.aws.s3.buckets) > 0
    res := result.new("NO BUCKETS", input.aws.s3.buckets[_])
}
