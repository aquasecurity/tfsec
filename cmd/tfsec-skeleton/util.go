package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
)

func listFiles(dir, pattern string) ([]os.FileInfo, error) {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	filteredFiles := []os.FileInfo{}
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		matched, err := regexp.MatchString(pattern, file.Name())
		if err != nil {
			return nil, err
		}
		if matched {
			filteredFiles = append(filteredFiles, file)
		}
	}
	return filteredFiles, nil
}

func calculateNextCode(provider string) (string, error) {
	files, err := listFiles("internal/app/tfsec/checks", fmt.Sprintf("%s.*", provider))
	if err != nil {
		return "", err
	}
	re := regexp.MustCompile("[0-9]+")
	maxCode := 0
	for _, file := range files {
		thisCode, _ := strconv.Atoi(strings.Join(re.FindAllString(file.Name(), -1), ""))
		if thisCode > maxCode {
			maxCode = thisCode
		}
	}
	return fmt.Sprintf("%03d", maxCode+1), nil
}

func verifyCheckPath(checkPath string) error {
	stat, _ := os.Stat(checkPath)
	if stat != nil {
		return errors.New(fmt.Sprintf("file [%s] already exists so not creating check", checkPath))
	}
	return nil
}
