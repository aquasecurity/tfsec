package block

import (
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/stretchr/testify/assert"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/gocty"
)

func Test_ContextVariables(t *testing.T) {
	underlying := &hcl.EvalContext{}
	ctx := NewContext(underlying, nil)

	val, err := gocty.ToCtyValue("hello", cty.String)
	if err != nil {
		t.Fatal(err)
	}

	ctx.Set(val, "my", "value")
	value := underlying.Variables["my"].AsValueMap()["value"]
	assert.Equal(t, "hello", value.AsString())

}
