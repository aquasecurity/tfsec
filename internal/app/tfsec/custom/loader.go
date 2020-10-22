package custom

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"strings"
)

type ChecksFile struct {
	Checks []*Check `json:"checks"`
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
	files, err := listFiles(customCheckDir, ".*_tfchecks.json")
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
	checkJson, err := ioutil.ReadFile(checkFilePath)
	if err != nil {
		return checks, err
	}
	err = json.Unmarshal(checkJson, &checks)
	if err != nil {
		return checks, err
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
