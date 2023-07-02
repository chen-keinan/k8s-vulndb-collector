package doc

import (
	"bytes"
	"encoding/json"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
)

type Vulnerability struct {
	ID              string    `json:"version,omitempty"`
	CreatedAt       string    `json:"created_at,omitempty"`
	Summary         string    `json:"summary,omitempty"`
	Description     string    `json:"description,omitempty"`
	AffectedVersion []Version `json:"affected_version,omitempty"`
	FixedVersion    []Version `json:"fixed_version,omitempty"`
	Urls            []string  `json:"urls,omitempty"`
	ExrenalUrls     []string  `json:"exretnal_urls,omitempty"`
}

type K8sVulnDB struct {
	Vulnerabilities []Vulnerability
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
		err = gm.Convert([]byte(contentText), vulnDoc)
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
		}
		vulnerabilities = append(vulnerabilities, vulnerability)
	}
	return &K8sVulnDB{
		Vulnerabilities: vulnerabilities,
	}, nil
}
