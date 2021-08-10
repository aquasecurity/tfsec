package test

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_AllRulesWereInitialised(t *testing.T) {
	rulesDir, err := filepath.Abs(strings.ReplaceAll("../rules", "/", string(os.PathSeparator)))
	if err != nil {
		t.Fatal(err)
	}
	initData, err := ioutil.ReadFile(filepath.Join(rulesDir, "init.go"))
	if err != nil {
		t.Fatal(err)
	}

	packages, err := findPackages(rulesDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range packages {
		fullPath := fmt.Sprintf("github.com/aquasecurity/tfsec/internal/app/tfsec/rules/%s", pkg)
		if !strings.Contains(string(initData), `"`+fullPath+`"`) {
			t.Errorf("init.go does not contain the rule package '%s'", fullPath)
		}
	}

}

func findPackages(dir string) ([]string, error) {

	packages := make(map[string]struct{})
	if err := filepath.Walk(dir, func(path string, f os.FileInfo, err error) error {
		if f.IsDir() {
			return err
		}
		if filepath.Base(path) == "init.go" {
			return err
		}
		sub := filepath.Dir(path)
		packages[filepath.Base(filepath.Dir(sub))+"/"+filepath.Base(sub)] = struct{}{}
		return err
	}); err != nil {
		return nil, err
	}

	var packageList []string

	for pkg := range packages {
		packageList = append(packageList, pkg)
	}

	return packageList, nil
}
