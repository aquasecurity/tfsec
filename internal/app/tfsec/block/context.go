package block

import (
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

type Context struct {
	ctx    *hcl.EvalContext
	parent *Context
}

func NewContext(ctx *hcl.EvalContext, parent *Context) *Context {
	if ctx.Variables == nil {
		ctx.Variables = make(map[string]cty.Value)
	}
	return &Context{
		ctx:    ctx,
		parent: parent,
	}
}

func (c *Context) NewChild() *Context {
	return NewContext(c.ctx.NewChild(), c)
}

func (c *Context) Parent() *Context {
	return c.parent
}

func (c *Context) Inner() *hcl.EvalContext {
	return c.ctx
}

func (c *Context) Root() *Context {
	root := c
	for {
		if root.Parent() == nil {
			break
		}
		root = root.Parent()
	}
	return root
}

func (c *Context) Get(parts ...string) cty.Value {
	if len(parts) == 0 {
		return cty.NilVal
	}
	src := c.ctx.Variables
	for i, part := range parts {
		if i == len(parts)-1 {
			return src[part]
		}
		src = src[part].AsValueMap()
	}
	return cty.NilVal
}

func (c *Context) GetByDot(path string) cty.Value {
	return c.Get(strings.Split(path, ".")...)
}

func (c *Context) SetByDot(val cty.Value, path string) {
	c.Set(val, strings.Split(path, ".")...)
}

func (c *Context) Set(val cty.Value, parts ...string) {
	if len(parts) == 0 {
		return
	}
	c.ctx.Variables[parts[0]] = mergeVars(c.ctx.Variables[parts[0]], parts[1:], val)
}

func mergeVars(src cty.Value, parts []string, value cty.Value) cty.Value {
	if len(parts) == 0 {
		return value
	}
	data := make(map[string]cty.Value)
	if src.Type().IsObjectType() && !src.IsNull() && src.LengthInt() > 0 {
		data = src.AsValueMap()
	}
	if len(parts) == 1 {
		data[parts[0]] = value
		return cty.ObjectVal(data)
	}
	data[parts[0]] = mergeVars(cty.ObjectVal(data), parts[1:], value)
	return cty.ObjectVal(data)
}
