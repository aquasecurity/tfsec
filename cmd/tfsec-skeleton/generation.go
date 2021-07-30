package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"text/template"

	"github.com/liamg/clinch/prompt"
)

var providers = []string{
	"AWS",
	"Azure",
	"DigitalOcean",
	"General",
	"GitHub",
	"Google",
	"Kubernetes",
	"OpenStack",
	"Oracle",
}

func writeTemplate(checkPath string, checkTmpl *template.Template, definition Definition) error {
	checkFile, err := os.Create(checkPath)
	if err != nil {
		return err
	}
	defer func() { _ = checkFile.Close() }()
	err = checkTmpl.Execute(checkFile, definition)
	if err != nil {
		return err
	}

	return nil
}

func verifyPathDoesNotExist(checkPath string, forceOverwrite bool) error {
	stat, _ := os.Stat(checkPath)
	if stat != nil {
		file, err := ioutil.ReadFile(checkPath)
		if err != nil {
			return err
		}
		if strings.Contains(string(file), "// generator-locked") {
			return fmt.Errorf("file [%s] is locked for update, remove comment to overwrite", checkPath)
		}

		if !forceOverwrite {
			return fmt.Errorf("file [%s] already exists so not creating check", checkPath)
		}
	}
	return nil
}

func inputYesNo(msg string) bool {
	failForDefaultStr := prompt.EnterInputWithDefault(fmt.Sprintf("%s (Y/n)", msg), "y")
	return strings.ToLower(failForDefaultStr[0:1]) == "y"
}

func enterInterfaceValue(msg string) interface{} {
	raw := prompt.EnterInput(msg)

	return convertToInterface(raw)
}

func convertToInterface(raw string) interface{} {

	if strings.Contains(raw, ",") {
		return strings.Split(raw, ",")
	}

	lower := strings.ToLower(raw)
	if lower == "true" || lower == "false" {
		return lower == "true"
	}

	if i, err := strconv.Atoi(raw); err == nil {
		return i
	}

	return raw
}

func findDocLink(provider string, blockType string, blockLabel string, attribute string) string {
	provider = strings.ToLower(provider)
	typeStr := "resources"
	shortCode := "r"
	if blockType == "data" {
		typeStr = "data-sources"
		shortCode = "d"
	}

	if urlIsGood(fmt.Sprintf(
		"https://raw.githubusercontent.com/hashicorp/terraform-provider-%s/master/website/docs/%s/%s.html.markdown",
		provider,
		shortCode,
		blockLabel,
	)) {
		return fmt.Sprintf(
			"https://registry.terraform.io/providers/hashicorp/%s/latest/docs/%s/%s#%s",
			provider,
			typeStr,
			blockLabel,
			attribute,
		)
	}

	shortBlock := strings.TrimPrefix(blockLabel, provider+"_")
	if urlIsGood(fmt.Sprintf(
		"https://raw.githubusercontent.com/hashicorp/terraform-provider-%s/master/website/docs/%s/%s.html.markdown",
		provider,
		shortCode,
		shortBlock,
	)) {
		return fmt.Sprintf(
			"https://registry.terraform.io/providers/hashicorp/%s/latest/docs/%s/%s#%s",
			provider,
			typeStr,
			shortBlock,
			attribute,
		)
	}

	return ""
}

func urlIsGood(url string) bool {
	resp, err := http.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode < 400
}
