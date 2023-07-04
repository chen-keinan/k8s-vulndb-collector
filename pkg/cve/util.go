package cve

import (
	"fmt"
	"github.com/aquasecurity/go-version/pkg/version"
	"github.com/goark/go-cvss/v3/metric"
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

func versionParts(line string) ([]string, string) {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "-")
	sign := "-"
	signs := []string{"<=", ">=", "<", ">"}
	for _, s := range signs {
		if strings.Contains(line, s) {
			sign = s
			break
		}
	}
	if sign != "-" {
		line = strings.ReplaceAll(line, sign, "")
	}
	updatedLine := fmt.Sprintf(" %s", line)
	findVersionParts := make([]string, 0)
	versionRex := `(?P<name>[^\s]+)?\s+v?(?P<version>\d+\.\d+\.\d+).*.v?(?P<version2>\d+\.\d+\.\d+)|\s*(\d+\.\d+\.\d+)\s*|(?P<name2>[^\s]+)?\s+v?(?P<version3>\d+\.\d+\.\d+)`
	regex := regexp.MustCompile(versionRex)
	parts := regex.FindStringSubmatch(updatedLine)
	for i, p := range parts {
		if i == 0 {
			continue
		}
		if len(p) == 0 {
			continue
		}
		findVersionParts = append(findVersionParts, p)
		if len(findVersionParts) == 1 && sign == "-" {
			sign = ""
		}
	}
	return findVersionParts, sign
}

func updatedLine(versionParts []string, sign string) string {
	switch len(versionParts) {
	case 1:
		return fmt.Sprintf("- %s v%s", sign, versionParts[0])
	case 2:
		var oneVersion bool
		var twoVersion bool
		if _, err := version.Parse(versionParts[0]); err == nil {
			oneVersion = true
		}
		if _, err := version.Parse(versionParts[1]); err == nil && oneVersion {
			twoVersion = true
			oneVersion = false
		} else {
			oneVersion = true
		}
		if twoVersion {
			return fmt.Sprintf("- v%s - v%s", versionParts[0], versionParts[1])
		}
		if oneVersion {
			return fmt.Sprintf("- %s %s v%s", versionParts[0], sign, versionParts[1])
		}
	case 3:
		return fmt.Sprintf("- %s v%s - v%s", versionParts[0], versionParts[1], versionParts[2])
	}
	return ""
}

func cvssVectorToScore(vector string) (string, float64) {
	bm, err := metric.NewBase().Decode(vector) //CVE-2020-1472: ZeroLogon
	if err != nil {
		return "", 0.0
	}
	return bm.Severity().String(), bm.Score()
}
