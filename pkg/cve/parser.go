package cve

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aquasecurity/go-version/pkg/version"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
)

const (
	paragraph = `^\*[\s\S]*\*$`
	versions  = `\s*(\d+\.\d+\.\d+)\s*`
	header    = `(^#{1,6}\s*[\S]+)`
)

type Vulnerability struct {
	ID              string    `json:"id,omitempty"`
	CreatedAt       string    `json:"created_at,omitempty"`
	Summary         string    `json:"summary,omitempty"`
	Component       string    `json:"component,omitempty"`
	Description     string    `json:"description,omitempty"`
	AffectedVersion []Version `json:"affected_version,omitempty"`
	FixedVersion    []Version `json:"fixed_version,omitempty"`
	Urls            []string  `json:"urls,omitempty"`
	Cvss            string    `json:"cvss,omitempty"`
	Severity        string    `json:"severity,omitempty"`
	Score           float64   `json:"score,omitempty"`
}

type K8sVulnDB struct {
	Cves []Vulnerability
}

func ParseVulneDB(vulnDB []byte) (*K8sVulnDB, error) {
	var db map[string]interface{}
	err := json.Unmarshal(vulnDB, &db)
	if err != nil {
		return nil, err
	}
	vulnerabilities := make([]Vulnerability, 0)
	for _, item := range db["items"].([]interface{}) {
		gm := goldmark.New(
			goldmark.WithExtensions(
				extension.GFM, // GitHub flavoured markdown.
			),
			goldmark.WithParserOptions(
				parser.WithAttribute(), // Enables # headers {#custom-ids}.
			),
			goldmark.WithRenderer(NewRenderer()),
		)
		vulnDoc := new(bytes.Buffer)
		i := item.(map[string]interface{})
		contentText := i["content_text"].(string)
		amendedDoc := AmendCveDoc(contentText)
		err = gm.Convert([]byte(amendedDoc), vulnDoc)
		if err != nil {
			return nil, err
		}
		var c Content
		err = json.Unmarshal(vulnDoc.Bytes(), &c)
		if err != nil {
			return nil, err
		}
		severity, score := cvssVectorToScore(c.Cvss)
		vulnerability := Vulnerability{
			ID:              i["id"].(string),
			Summary:         i["summary"].(string),
			Urls:            []string{i["url"].(string), i["external_url"].(string)},
			CreatedAt:       i["date_published"].(string),
			AffectedVersion: c.AffectedVersion,
			FixedVersion:    c.FixedVersion,
			Description:     c.Description,
			Component:       c.ComponentName,
			Cvss:            c.Cvss,
		}
		if len(severity) > 0 {
			vulnerability.Severity = severity
			vulnerability.Score = score
		}
		vulnerabilities = append(vulnerabilities, vulnerability)
	}
	return &K8sVulnDB{
		Cves: vulnerabilities,
	}, nil
}
func AmendCveDoc(doc string) string {
	var lineWriter bytes.Buffer
	docReader := strings.NewReader(doc)
	fileScanner := bufio.NewScanner(docReader)
	fileScanner.Split(bufio.ScanLines)
	var startAffected, endAffected bool
	var startFixed, endFixed bool
	for fileScanner.Scan() {
		line := fileScanner.Text()
		if endAffected && endFixed {
			break
		}
		if matchRegEx(paragraph, line) || matchRegEx(header, line) {
			if strings.Contains(strings.ToLower(line), "affected versions") {
				line = "#### Affected Versions"
				lineWriter.WriteString(fmt.Sprintf("%s\n", line))
				startAffected = true
				continue
			}
			if strings.Contains(strings.ToLower(line), "fixed versions") {
				line = "#### Fixed Versions"
				lineWriter.WriteString(fmt.Sprintf("%s\n", line))
				startFixed = true
				endAffected = true
				continue
			}
		}
		// add description
		if !(startAffected || startFixed) {
			lineWriter.WriteString(fmt.Sprintf("%s\n", line))
			continue
		}
		// complete version parsing
		if matchRegEx(header, line) && !strings.Contains(strings.ToLower(line), "fixed versions") && startFixed {
			endFixed = true
		}

		if len(strings.TrimSpace(line)) == 0 {
			continue
		}
		vp, sign := versionParts(line)
		if len(vp) > 0 {
			line = updatedLine(vp, sign)
			lineWriter.WriteString(fmt.Sprintf("%s\n", line))
			continue
		}
	}
	return lineWriter.String()
}

func ValidateCveData(cves []Vulnerability) {
	for _, cve := range cves {
		// validate id
		if len(cve.ID) == 0 {
			fmt.Printf("id is mssing on cve #%s", cve.ID)
		}
		if len(cve.CreatedAt) == 0 {
			fmt.Printf("CreatedAt is mssing on cve #%s", cve.ID)
		}
		if len(cve.Summary) == 0 {
			fmt.Printf("Summary is mssing on cve #%s", cve.ID)
		}
		if len(strings.TrimPrefix(cve.Component, upstreamRepo)) == 0 {
			fmt.Printf("Component is mssing on cve #%s", cve.ID)
		}
		if len(cve.Description) == 0 {
			fmt.Printf("Description is mssing on cve #%s", cve.ID)
		}
		/*
			if len(cve.AffectedVersion) == 0 {
				fmt.Println(fmt.Sprintf("AffectedVersion is mssing on cve #%s", cve.ID))
			}*/
		if len(cve.AffectedVersion) > 0 {
			for _, v := range cve.AffectedVersion {
				_, err := version.Parse(v.From)
				if err != nil {
					fmt.Printf("AffectedVersion From %s is invalid on cve #%s", v.From, cve.ID)
				}
				_, err = version.Parse(v.To)
				if err != nil {
					fmt.Printf("AffectedVersion To %s is invalid on cve #%s", v.To, cve.ID)
				}
			}
		}

		if len(cve.FixedVersion) > 0 {
			for _, v := range cve.FixedVersion {
				_, err := version.Parse(v.Fixed)
				if err != nil {
					fmt.Printf("FixedVersion Fixed %s is invalid on cve #%s", v.From, cve.ID)
				}
			}
		}
		if len(cve.Urls) == 0 {
			fmt.Printf("Urls is mssing on cve #%s", cve.ID)
		}
	}
}
