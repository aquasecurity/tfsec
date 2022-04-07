package custom.rego.rego.sauce

import data.lib.defsec

deny[res] {
    count(input.aws.s3.buckets) > 0
    res := defsec.result("NO BUCKETS", input.aws.s3.buckets[_])
}
