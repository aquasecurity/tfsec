package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/pkg/security"
)

func TestIsSensitiveAttribute(t *testing.T) {
	t.Parallel() // marks TLog as capable of running in parallel with other tests
	tests := []struct {
		name     string
		expected bool
	}{
		{"crap", false},
		{"secret", true},
		{"blob", false},
		{"somekindofsecrets", true},
		{"bigcorp_eks_aux__externalsecrets_bingo_version", false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel() // marks each test case as capable of running in parallel with each other
			if security.IsSensitiveAttribute(tt.name) != tt.expected {
				t.Errorf("IsSensitiveAttribute(\"%v\") != %v", tt.name, tt.expected)
			}
		})
	}
}
