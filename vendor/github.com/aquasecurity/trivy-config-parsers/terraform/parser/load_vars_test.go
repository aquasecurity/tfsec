package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zclconf/go-cty/cty"
)

func Test_JsonVarsFile(t *testing.T) {

	path := createTestFile("test.tfvars.json", `
{
	"variable": {
		"foo": {
			"default": "bar"
		},
		"baz": "qux"
	},
	"foo2": true,
	"foo3": 3
}
`,
	)

	vars, _ := LoadTFVars([]string{path})
	assert.Equal(t, "bar", vars["variable"].GetAttr("foo").GetAttr("default").AsString())
	assert.Equal(t, "qux", vars["variable"].GetAttr("baz").AsString())
	assert.Equal(t, true, vars["foo2"].True())
	assert.Equal(t, true, vars["foo3"].Equals(cty.NumberIntVal(3)).True())
}
