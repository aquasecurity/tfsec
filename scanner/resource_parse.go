package scanner

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/hcl/token"

	"github.com/hashicorp/hcl/hcl/ast"
)

var ErrParamNotFound = fmt.Errorf("Parameter not found")
var ErrIgnored = fmt.Errorf("Parameter ignored")

type Resource struct {
	Type       string
	Name       string
	parameters []Parameter
	pos        token.Pos
	comment    string
}

type ParameterList []Parameter

type Parameter struct {
	pos     token.Pos
	name    string
	value   interface{}
	comment string
}

func (p Parameter) Ignored() bool {
	return strings.Contains(p.comment, "tfsec:ignore")
}

func (p Parameter) Value() interface{} {
	return p.value
}

func (p Parameter) String() string {

	if s, ok := p.value.(string); ok {
		return s
	}

	if i, ok := p.value.(int64); ok {
		return fmt.Sprintf("%d", i)
	}

	if f, ok := p.value.(float64); ok {
		return fmt.Sprintf("%f", f)
	}

	if b, ok := p.value.(bool); ok {
		return fmt.Sprintf("%t", b)
	}

	return ""
}

func (p Parameter) StringList() []string {

	if s, ok := p.value.([]string); ok {
		return s
	}

	if s, ok := p.value.([]interface{}); ok {
		output := []string{}
		for _, iface := range s {
			if str, ok := iface.(string); ok {
				output = append(output, str)
			}
		}
		return output
	}

	return []string{}
}

func (p Parameter) Get(name string) (Parameter, error) {
	if parameters, ok := p.value.([]Parameter); ok {
		for _, p := range parameters {
			if p.name == name {
				if p.Ignored() {
					return p, ErrIgnored
				}
				return p, nil
			}
		}
	}
	return Parameter{}, ErrParamNotFound
}

func (r Resource) Ignored() bool {
	return strings.Contains(r.comment, "tfsec:ignore")
}

func (r Resource) Get(name string) (Parameter, error) {
	for _, p := range r.parameters {
		if p.name == name {
			if p.Ignored() {
				return p, ErrIgnored
			}
			return p, nil
		}
	}
	return Parameter{}, ErrParamNotFound
}

func (r Resource) String() string {
	return fmt.Sprintf("%s.%s", r.Type, r.Name)
}

func ParseResource(item *ast.ObjectItem) (Resource, error) {

	res := Resource{}

	if len(item.Keys) != 3 || item.Keys[0].Token.Text != "resource" {
		return res, fmt.Errorf("Resource declaration is invalid")
	}

	res.Type = item.Keys[1].Token.Text[1 : len(item.Keys[1].Token.Text)-1]
	res.Name = item.Keys[2].Token.Text[1 : len(item.Keys[2].Token.Text)-1]

	ot, ok := item.Val.(*ast.ObjectType)
	if !ok {
		return res, fmt.Errorf("Resource declaration is invalid")
	}

	res.parameters = []Parameter{}

	for _, item := range ot.List.Items {
		if len(item.Keys) == 1 {
			param, err := parseParam(item)
			if err != nil {
				return res, err
			}
			res.parameters = append(res.parameters, param)
		}
	}

	res.pos = item.Keys[0].Token.Pos
	for _, comment := range item.LeadComment.List {
		res.comment += comment.Text + " "
	}
	for _, comment := range item.LineComment.List {
		res.comment += comment.Text + " "
	}

	return res, nil
}

func parseParam(item *ast.ObjectItem) (Parameter, error) {

	if len(item.Keys) == 0 {
		return Parameter{}, fmt.Errorf("parameter has no keys")
	}

	param := Parameter{
		name: item.Keys[0].Token.Text,
		pos:  item.Keys[0].Token.Pos,
	}

	for _, comment := range item.LeadComment.List {
		param.comment += comment.Text + " "
	}
	for _, comment := range item.LineComment.List {
		param.comment += comment.Text + " "
	}

	var err error
	switch v := item.Val.(type) {
	case *ast.LiteralType:
		param.value, err = getLiteralType(v)
	case *ast.ObjectType:
		childParams := []Parameter{}
		for _, item := range v.List.Items {
			if len(item.Keys) == 1 {
				v, err := parseParam(item)
				if err != nil {
					return param, err
				}
				childParams = append(childParams, v)
			}
		}
		param.value = childParams
	case *ast.ListType:
		list := []interface{}{}
		for _, item := range v.List {
			if lt, ok := item.(*ast.LiteralType); ok {
				if t, err := getLiteralType(lt); err == nil {
					list = append(list, t)
				}
			}
		}
		param.value = list
	default:
		err = fmt.Errorf("cannot parse unsupported type: %T", item.Val)
	}

	return param, err
}

func getLiteralType(v *ast.LiteralType) (interface{}, error) {
	switch v.Token.Type {
	case token.NUMBER:
		return strconv.ParseInt(strings.Replace(v.Token.Text, "\"", "", -1), 10, 64)
	case token.FLOAT:
		return strconv.ParseFloat(strings.Replace(v.Token.Text, "\"", "", -1), 64)
	case token.BOOL:
		return strconv.ParseBool(strings.Replace(v.Token.Text, "\"", "", -1))
	case token.STRING:
		return v.Token.Text[1 : len(v.Token.Text)-1], nil
	}
	return nil, fmt.Errorf("Unknown type %T", v)
}
