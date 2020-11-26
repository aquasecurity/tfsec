package custom

import (
	"encoding/json"
	"errors"
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

type ChecksFile struct {
	Checks []*Check `json:"checks" yaml:"checks"`
}

func Load(customCheckDir string) error {
	_, err := os.Stat(customCheckDir)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}

	return loadCustomChecks(customCheckDir)
}

func loadCustomChecks(customCheckDir string) error {
	files, err := listFiles(customCheckDir, ".*_tfchecks.*")
	if err != nil {
		return err
	}
	var errorList []string
	for _, file := range files {
		checkFilePath := path.Join(customCheckDir, file.Name())
		err = Validate(checkFilePath)
		if err != nil {
			errorList = append(errorList, err.Error())
			continue
		}
		checks, err := loadCheckFile(checkFilePath)
		if err != nil {
			errorList = append(errorList, err.Error())
			continue
		}

		processFoundChecks(checks)
	}

	if len(errorList) > 0 {
		return errors.New(strings.Join(errorList, "\n"))
	}
	return nil
}

func loadCheckFile(checkFilePath string) (ChecksFile, error) {
	var checks ChecksFile
	checkFileContent, err := ioutil.ReadFile(checkFilePath)
	if err != nil {
		return checks, err
	}
	ext := filepath.Ext(checkFilePath)
	switch strings.ToLower(ext) {
	case ".json":
		err = json.Unmarshal(checkFileContent, &checks)
		if err != nil {
			return checks, err
		}
	case ".yml":
	case ".yaml":
		err = yaml.Unmarshal(checkFileContent, &checks)
		if err != nil {
			return checks, nil
		}
	default:
		return checks, fmt.Errorf("couldn't process the file %s", checkFilePath)
	}

	return checks, nil
}

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
