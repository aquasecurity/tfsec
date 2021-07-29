package examples

import (
	"fmt"
	"strings"
)

/*
 SetAttribute sets a given attribute value from a dot separated hcl path. resource paths should be prefixed with "resource."
	This assumes a certain standard of clean Terraform code as is available in the provider examples.
	It's used for building rule example code and thus only builds an approximation of what is needed, to be manually tweaked afterwards.
*/
func SetAttribute(rawHCL string, dotPath string, value interface{}, renameResource string) string {

	var stack []string
	var inPath bool
	var found bool
	var output []string
	var tabStr = "\t"
	var tabChecked bool
	var multilineMarker string

	for _, line := range strings.Split(rawHCL, "\n") {

		if multilineMarker != "" {
			if line == multilineMarker {
				multilineMarker = ""
			}
			output = append(output, line)
			continue
		}

		if !tabChecked && strings.TrimPrefix(line, " ") != line {
			var size int
			for _, c := range line {
				if c == ' ' {
					size++
					continue
				}
				break
			}
			tabChecked = true
			tabStr = strings.Repeat(" ", size)
		}

		if strings.Contains(line, "=") {
			// handle attribute definition
			parts := strings.Split(line, "=")
			name := strings.TrimSpace(parts[0])
			if strings.Join(append(stack, name), ".") == dotPath {
				line = fmt.Sprintf("%s= %s", parts[0], sprintGo(value))
				found = true
			}
			if strings.Contains(line, "<<") {
				multilineMarker = strings.Split(line, "<<")[1]
			}
			if strings.HasSuffix(line, "{") {
				stack = append(stack, name)
			}
		} else if strings.HasSuffix(strings.TrimSpace(line), "{") {
			if renameResource != "" && len(strings.Split(dotPath, ".")) >= 3 {
				if dotSegmentFromLine(line) == strings.Join(strings.Split(dotPath, ".")[:3], ".") {
					parts := strings.Split(strings.TrimSpace(line), " ")
					line = fmt.Sprintf("%s %s \"%s\" {", parts[0], parts[1], renameResource)
				}
			}
			stack = append(stack, dotSegmentFromLine(line))
		} else if strings.HasSuffix(strings.TrimSpace(line), "}") {
			if inPath && !found {
				// we were in the right place - did we find our attr? if not, we need to add it
				inject := expandPathAndValue(strings.TrimPrefix(dotPath, strings.Join(stack, ".")+"."), value, tabStr, len(stack))
				output = append(output, inject)
				found = true
			}

			stack = stack[:len(stack)-1]
		}

		inPath = strings.HasPrefix(dotPath, strings.Join(stack, "."))
		output = append(output, line)
	}

	return strings.Join(output, "\n")
}

func expandPathAndValue(dotPath string, value interface{}, tabStr string, tabSize int) string {
	tab := strings.Repeat(tabStr, tabSize)
	segments := strings.Split(dotPath, ".")
	if len(segments) == 1 {
		return fmt.Sprintf("%s%s = %s", tab, segments[0], sprintGo(value))
	}

	return fmt.Sprintf("%s%s {\n%s\n%s}", tab, segments[0], expandPathAndValue(strings.Join(segments[1:], "."), value, tabStr, tabSize+1), tab)
}

func dotSegmentFromLine(line string) string {
	parts := strings.Split(strings.Split(strings.TrimSpace(line), "{")[0], " ")
	var output []string
	for i, part := range parts {
		if i == 2 {
			part = "*"
		}
		part = strings.ReplaceAll(part, `"`, "")
		if part == "" {
			continue
		}
		output = append(output, part)
	}
	return strings.Join(output, ".")
}

func sprintGo(value interface{}) string {
	if s, ok := value.(string); ok {
		return fmt.Sprintf("%q", s)
	}
	if s, ok := value.([]string); ok {
		return fmt.Sprintf("%#v", s)
	}
	return fmt.Sprintf("%v", value)
}
