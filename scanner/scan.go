package scanner

import (
	"fmt"

	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/hashicorp/hcl/hcl/parser"
)

func Scan(src []byte) ([]Result, error) {
	f, err := parser.Parse(src)
	if err != nil {
		return nil, err
	}

	objectList, ok := f.Node.(*ast.ObjectList)
	if !ok {
		return nil, fmt.Errorf("unknown error: failed to parse HCL")
	}

	results := []Result{}

	for _, item := range objectList.Items {
		if len(item.Keys) > 0 {
			switch item.Keys[0].Token.Text {
			case "resource":
				resource, err := ParseResource(item)
				if err != nil {
					return nil, err
				}
				r := scanResource(resource)
				results = append(results, r...)

			case "data":
			case "variable":
			}
		}
	}

	return results, nil
}
