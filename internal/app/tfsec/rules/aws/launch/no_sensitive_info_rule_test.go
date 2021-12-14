package launch
 
 import (
 	"strings"
 	"testing"
 
 	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
 )
 
 func Test_AWSNoSensitiveInfo_FailureExamples(t *testing.T) {
 	expectedCode := "aws-launch-no-sensitive-info"
 
 	rule, err := scanner.GetRuleById(expectedCode)
 	if err != nil {
 		t.FailNow()
 	}
 	for i, badExample := range rule.Documentation.BadExample {
 		t.Logf("Running bad example for '%s' #%d", expectedCode, i+1)
 		if strings.TrimSpace(badExample) == "" {
 			t.Fatalf("bad example code not provided for %s", rule.ID())
 		}
 		defer func() {
 			if err := recover(); err != nil {
 				t.Fatalf("Scan (bad) failed: %s", err)
 			}
 		}()
 		results := testutil.ScanHCL(badExample, t)
 		testutil.AssertCheckCode(t, rule.ID(), "", results)
 	}
 }
 
 func Test_AWSNoSensitiveInfo_SuccessExamples(t *testing.T) {
 	expectedCode := "aws-launch-no-sensitive-info"
 
 	rule, err := scanner.GetRuleById(expectedCode)
 	if err != nil {
 		t.FailNow()
 	}
 	for i, example := range rule.Documentation.GoodExample {
 		t.Logf("Running good example for '%s' #%d", expectedCode, i+1)
 		if strings.TrimSpace(example) == "" {
 			t.Fatalf("good example code not provided for %s", rule.ID())
 		}
 		defer func() {
 			if err := recover(); err != nil {
 				t.Fatalf("Scan (good) failed: %s", err)
 			}
 		}()
 		results := testutil.ScanHCL(example, t)
 		testutil.AssertCheckCode(t, "", rule.ID(), results)
 	}
 }
