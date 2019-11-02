package security

import (
	"strings"
)

func IsSensitiveAttribute(name string) bool {

	// TODO add a whole bunch of regular expressions in here

	name = strings.ToLower(name)

	switch {
	case
		strings.Contains(name, "password"),
		strings.Contains(name, "secret"),
		strings.Contains(name, "private_key"),
		strings.Contains(name, "aws_access_key_id"),
		strings.Contains(name, "aws_secret_access_key"),
		strings.Contains(name, "token"),
		strings.Contains(name, "api_key"):
		return true
	}

	return false
}
