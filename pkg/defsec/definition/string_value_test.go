package definition

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_StringValueEqualTo(t *testing.T) {
	testCases := []struct {
		desc       string
		input      string
		check     string
		ignoreCase bool
		expected   bool
	}{
		{
			desc:       "return truw when string is equal",
			input:      "something",
			check:     "",
			expected:   false,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {

		})
	}
}

func Test_StringValueStartsWith(t *testing.T) {
	testCases := []struct {
		desc       string
		input      string
		prefix     string
		ignoreCase bool
		expected   bool
	}{
		{
			desc:     "return true when starts with",
			input:    "something",
			prefix:   "some",
			expected: true,
		},
		{
			desc:     "return false when does not start with",
			input:    "something",
			prefix:   "nothing",
			expected: false,
		},
		{
			desc:       "return true when starts with",
			input:      "something",
			prefix:     "SOME",
			ignoreCase: true,
			expected:   true,
		},
		{
			desc:     "return false when does not start with",
			input:    "something",
			prefix:   "SOME",
			expected: false,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {

			val := StringValue{
				Value: tC.input,
			}

			var options []StringEqualityOption

			if tC.ignoreCase {
				options = append(options, IgnoreCase)
			}

			assert.Equal(t, tC.expected, val.StartsWith(tC.prefix, options...))
		})
	}
}
