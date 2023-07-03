package doc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

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
	ExrenalUrls     []string  `json:"exretnal_urls,omitempty"`
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
		amendedDoc := amendDoc(contentText)
		//		fmt.Print(amendedDoc)
		err = gm.Convert([]byte(amendedDoc), vulnDoc)
		if err != nil {
			return nil, err
		}
		var c Content
		err = json.Unmarshal(vulnDoc.Bytes(), &c)
		if err != nil {
			return nil, err
		}
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
		vulnerabilities = append(vulnerabilities, vulnerability)
	}
	return &K8sVulnDB{
		Cves: vulnerabilities,
	}, nil
}

func amendDoc(doc string) string {
	var lineWriter bytes.Buffer
	docReader := strings.NewReader(doc)
	fileScanner := bufio.NewScanner(docReader)
	fileScanner.Split(bufio.ScanLines)
	var prevHeader string
	for fileScanner.Scan() {
		line := fileScanner.Text()
		if matchRegEx(paragraph, line) {
			if strings.Contains(strings.ToLower(line), "affected versions") {
				lineWriter.WriteString(fmt.Sprintf("%s\n", "#### Affected Versions"))
				continue
			}
			if strings.Contains(strings.ToLower(line), "fixed versions") {
				lineWriter.WriteString(fmt.Sprintf("%s\n", "#### Fixed Versions"))
				continue
			}
		}
		if matchRegEx(versions, line) && !strings.HasPrefix(line, "-") {
			lineWriter.WriteString(fmt.Sprintf("%s\n", fmt.Sprintf("- %s", line)))
			continue
		}
		if strings.Contains(strings.ToLower(prevHeader), "affected versions") ||
			strings.Contains(strings.ToLower(prevHeader), "fixed versions") {
			if len(strings.TrimSpace(line)) == 0 {
				continue
			}
		}
		if matchRegEx(header, line) {
			prevHeader = line
		}
		lineWriter.WriteString(fmt.Sprintf("%s\n", line))
	}
	return lineWriter.String()
}
