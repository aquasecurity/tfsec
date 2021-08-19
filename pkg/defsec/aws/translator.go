package aws

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/defsec/definition"
)

type AWS struct {
}

func main() {
	str := definition.StringValue{}

	fmt.Println(str.EndLine)

}
