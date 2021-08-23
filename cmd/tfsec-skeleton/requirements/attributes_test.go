package requirements

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_AttributeMustHaveValue(t *testing.T) {
	requirement := AttributeMustHaveValue("resource", "made_up_resource", "settings.encryption.enabled", true, true, "")

	assert.Equal(t, `
resource "made_up_resource" "good_example" {
	settings {
		encryption {
			enabled = true
		}
	}
}
`, requirement.GenerateGoodExample())

	assert.Equal(t, `
resource "made_up_resource" "bad_example" {
	settings {
		encryption {
			enabled = false
		}
	}
}
`, requirement.GenerateBadExample())

	assert.Equal(t, `if enabledAttr := resourceBlock.GetBlock("settings").GetBlock("encryption").GetAttribute("enabled"); enabledAttr.IsNil() { // alert on use of default value
				set.AddResult().
					WithDescription("Resource '%s' uses default value for settings.encryption.enabled", resourceBlock.FullName())
			} else if enabledAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' does not have settings.encryption.enabled set to true", resourceBlock.FullName()).
					WithAttribute("")
			}`, requirement.GenerateRuleCode())

}

func Test_AttributeMustNotHaveValue(t *testing.T) {
	requirement := AttributeMustNotHaveValue("resource", "made_up_resource", "settings.lucky_number", 13, true, "")

	assert.Equal(t, `
resource "made_up_resource" "good_example" {
	settings {
		lucky_number = 14
	}
}
`, requirement.GenerateGoodExample())

	assert.Equal(t, `
resource "made_up_resource" "bad_example" {
	settings {
		lucky_number = 13
	}
}
`, requirement.GenerateBadExample())

	assert.Equal(t, `if luckyNumberAttr := resourceBlock.GetBlock("settings").GetAttribute("lucky_number"); luckyNumberAttr.IsNil() { // alert on use of default value
				set.AddResult().
					WithDescription("Resource '%s' uses default value for settings.lucky_number", resourceBlock.FullName())
			} else if luckyNumberAttr.Equals(13) {
				set.AddResult().
					WithDescription("Resource '%s' has settings.lucky_number set to 13", resourceBlock.FullName()).
					WithAttribute("")
			}`, requirement.GenerateRuleCode())

}
