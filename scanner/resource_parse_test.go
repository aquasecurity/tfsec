package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/hashicorp/hcl/hcl/parser"
	"github.com/stretchr/testify/require"
)

func TestResourceParsing(t *testing.T) {

	src := `
			resource "aws_s3_bucket" "my-bucket" {
				bucket = "my-tf-test-bucket"
				acl    = "private"

				tags = {
					Name        = "hello"
					Environment = "development"
				}
			}
	`

	f, err := parser.Parse([]byte(src))
	require.Nil(t, err, "farse failure")
	objectList, ok := f.Node.(*ast.ObjectList)
	require.True(t, ok, "HCL parser failure")
	res, err := ParseResource(objectList.Items[0])
	require.Nil(t, err, "resource parsing failed")

	assert.Equal(t, "aws_s3_bucket", res.Type)
	assert.Equal(t, "my-bucket", res.Name)

	p, err := res.Get("bucket")
	require.Nil(t, err)
	assert.Equal(t, p.String(), "my-tf-test-bucket")

	p, err = res.Get("acl")
	require.Nil(t, err)
	assert.Equal(t, p.String(), "private")

	tags, err := res.Get("tags")
	require.Nil(t, err)

	p, err = tags.Get("Name")
	require.Nil(t, err)
	assert.Equal(t, p.String(), "hello")

	p, err = tags.Get("Environment")
	require.Nil(t, err)
	assert.Equal(t, p.String(), "development")

}

func TestResourceListParsing(t *testing.T) {

	src := `
			resource "house" "my-house" {
				rooms = ["kitchen", "bedroom", "bathroom"]
			}
	`

	f, err := parser.Parse([]byte(src))
	require.Nil(t, err, "farse failure")
	objectList, ok := f.Node.(*ast.ObjectList)
	require.True(t, ok, "HCL parser failure")
	res, err := ParseResource(objectList.Items[0])
	require.Nil(t, err, "resource parsing failed")

	p, err := res.Get("rooms")
	require.Nil(t, err)
	assert.Equal(t, p.StringList(), []string{"kitchen", "bedroom", "bathroom"})

}
