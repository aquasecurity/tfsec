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
		nextPart := src[part]
		if nextPart == cty.NilVal {
			return cty.NilVal
		}
		src = nextPart.AsValueMap()
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

	/*
		{"mod_result": "ok"}

		module.my-mod
	*/

	// c.ctx.Variables["module"] = mergeVars(c.ctx.Variables["module"], "my-mod", {"mod_result": "ok"})
	c.ctx.Variables[parts[0]] = mergeVars(c.ctx.Variables[parts[0]], parts[1:], val)
}

func mergeVars(src cty.Value, parts []string, value cty.Value) cty.Value {

	// src = c.ctx.Variables["module"]
	// parts = "my-mod"
	// value = {"mod_result": "ok"}

	if len(parts) == 0 {
		if value.Type().IsObjectType() && !value.IsNull() && value.LengthInt() > 0 && src.Type().IsObjectType() && !src.IsNull() && src.LengthInt() > 0 {
			return mergeObjects(src, value)
		}
		return value
	}

	data := make(map[string]cty.Value)
	if src.Type().IsObjectType() && !src.IsNull() && src.LengthInt() > 0 {
		data = src.AsValueMap()
	}

	data[parts[0]] = mergeVars(src, parts[1:], value)

	return cty.ObjectVal(data)
}

func mergeObjects(a cty.Value, b cty.Value) cty.Value {
	output := make(map[string]cty.Value)
	for key, val := range a.AsValueMap() {
		output[key] = val
	}
	for key, val := range b.AsValueMap() {
		output[key] = val
	}
	return cty.ObjectVal(output)
}
