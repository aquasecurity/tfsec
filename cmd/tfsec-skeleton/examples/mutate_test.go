package examples

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Mutation(t *testing.T) {
	table := []struct {
		input  string
		path   string
		value  interface{}
		output string
	}{
		{
			input: `
resource "google_project" "example" {
	auto_create_network = true	
}
			`,
			path:  "resource.google_project.*.auto_create_network",
			value: false,
			output: `
resource "google_project" "example" {
	auto_create_network = false
}
			`,
		},
		{
			input: `
resource "google_project" "example" {
	name = "something"
}
			`,
			path:  "resource.google_project.*.auto_create_network",
			value: false,
			output: `
resource "google_project" "example" {
	name = "something"
	auto_create_network = false
}
			`,
		},
		{
			input: `
resource "computer" "example" {
	name = "something"
	settings {
		security {
			encryption {
				enabled = false
			}
		}
	}
}
			`,
			path:  "resource.computer.*.settings.security.encryption.enabled",
			value: true,
			output: `
resource "computer" "example" {
	name = "something"
	settings {
		security {
			encryption {
				enabled = true
			}
		}
	}
}
			`,
		},
		{
			input: `
resource "computer" "something" {
	name = "something"
}
			`,
			path:  "resource.computer.*.settings.security.encryption.enabled",
			value: true,
			output: `
resource "computer" "example" {
	name = "something"
	settings {
		security {
			encryption {
				enabled = true
			}
		}
	}
}
			`,
		},
	}

	for i, test := range table {
		t.Run(fmt.Sprintf("Case #%d", i), func(t *testing.T) {
			actual := SetAttribute(test.input, test.path, test.value, "example")
			assert.Equal(t, test.output, actual)
		})
	}
}
