package examples

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

func FindCode(provider string, blockType string, typeLabel string) (string, error) {

	var shortCode string
	switch blockType {
	case "resource":
		shortCode = "r"
	case "data":
		shortCode = "d"
	default:
		return "", fmt.Errorf("unsupported block type")
	}

	var urls []string

	provider = strings.ToLower(provider)

	switch provider {
	case "azure":
		provider = "azurerm"
	}

	urls = append(urls, fmt.Sprintf(
		"https://raw.githubusercontent.com/hashicorp/terraform-provider-%s/master/website/docs/%s/%s.html.markdown",
		provider,
		shortCode,
		typeLabel,
	))
	urls = append(urls, fmt.Sprintf(
		"https://raw.githubusercontent.com/hashicorp/terraform-provider-%s/master/website/docs/%s/%s.html.markdown",
		provider,
		shortCode,
		strings.TrimPrefix(typeLabel, provider+"_"),
	))

	var rawMarkdown string

	for _, url := range urls {
		if func(url string) bool {
			resp, err := http.Get(url)
			if err != nil {
				return false
			}
			defer resp.Body.Close()
			if resp.StatusCode >= 400 {
				return false
			}
			code, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return false
			}
			rawMarkdown = string(code)
			return true
		}(url) {
			break
		}
	}

	if rawMarkdown == "" {
		return "", fmt.Errorf("no docs found")
	}

	var example []string
	var inExample bool
	for _, line := range strings.Split(rawMarkdown, "\n") {
		if strings.HasPrefix(line, "```hcl") {
			inExample = true
			continue
		} else if strings.HasPrefix(line, "```") {
			break
		} else if inExample {
			example = append(example, strings.TrimSuffix(line, "\r"))
		}
	}

	return strings.Join(example, "\n"), nil
}
