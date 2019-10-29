package tfsec

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Ignore(t *testing.T) {

	results := scanSource(`
resource "aws_security_group_rule" "my-rule" {
    type        = "ingress"
    cidr_blocks = ["0.0.0.0/0"] // tfsec:ignore
}
`)
	assert.Len(t, results, 0)

}
