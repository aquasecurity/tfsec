package main

import (
	"os"
	"text/template"
)

func writeTemplate(contents interface{}, path string, tmpl *template.Template) {
	outputFile, err := os.Create(path)
	if err != nil {
		panic(err)
	}

	defer outputFile.Close()
	if err = tmpl.Execute(outputFile, contents); err != nil {
		panic(err)
	}
}
