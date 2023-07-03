package doc

import (
	"regexp"
	"strings"
)

func trimString(version string, trimValues []string) string {
	for _, v := range trimValues {
		version = strings.ReplaceAll(version, v, "")
	}
	return strings.TrimSpace(version)
}

func matchRegEx(regex string, value string) bool {
	headerRegex := regexp.MustCompile(regex)
	return len(headerRegex.FindStringSubmatch(value)) > 0

}
