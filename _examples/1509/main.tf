resource "aws_cloudfront_distribution" "bad_example" {
  default_cache_behavior {
    viewer_protocol_policy = "allow-all"
  }
  viewer_certificate {
    cloudfront_default_certificate = true
    minimum_protocol_version       = "TLSv1.0"
  }
}
