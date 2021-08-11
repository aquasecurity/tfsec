package block

import (
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

func (c *Context) SetByDot(path string, val cty.Value) {

}

type stackItem struct {
	object map[string]cty.Value
	name   string
}

func (c *Context) Set(val cty.Value, parts ...string) {

	object := c.ctx.Variables
	var stack []stackItem
	stack = append(stack, stackItem{object: object})

	for i, part := range parts {
		if i == len(parts)-1 {
			object[part] = val
			break
		}
		sub, ok := object[part]
		if !ok {
			data := make(map[string]cty.Value, 1)
			data["_"] = cty.NilVal
			object[part] = cty.ObjectVal(data)
			sub = object[part]
		}
		object = sub.AsValueMap()
		stack = append([]stackItem{{object: object, name: part}}, stack...)
	}

	for _, item := range stack {

	}

	c.ctx.Variables[parts[0]] = nil

}
