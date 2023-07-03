package doc

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"io"

	"github.com/aquasecurity/go-version/pkg/version"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	extAst "github.com/yuin/goldmark/extension/ast"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer"
)

var _ renderer.Renderer = &JSONRenderer{}

const (
	upstreamRepo = "github.com/kubernetes"
)

type JSONRenderer struct {
	document *Node          // Root node
	context  blockNodeStack // Track where we are in the structure of the document
}

type Node struct {
	Type       NodeType     `json:"type"`
	Version    int          `json:"version,omitempty"`
	Attributes *Attributes  `json:"attrs,omitempty"`
	Content    []*Node      `json:"content,omitempty"`
	Marks      []MarkStruct `json:"marks,omitempty"`
	Text       string       `json:"text,omitempty"`
}

func (n *Node) AddContent(c *Node) {
	n.Content = append(n.Content, c)
}

type Attributes struct {
	Width    float32 `json:"width,omitempty"`    // For media single
	Layout   Layout  `json:"layout,omitempty"`   // For media single
	Level    int     `json:"level,omitempty"`    // For headings
	Language string  `json:"language,omitempty"` // For fenced code blocks
}

type MarkStruct struct {
	Type       Mark            `json:"type,omitempty"`
	Attributes *MarkAttributes `json:"attrs,omitempty"`
}

type MarkAttributes struct {
	Href  string `json:"href,omitempty"`  // For links
	Title string `json:"title,omitempty"` // For links
}

// NodeType represents the type of a node
type NodeType string

// Node types
const (
	NodeTypeNone        = "none"
	NodeTypeBlockquote  = "blockquote"
	NodeTypeBulletList  = "bulletList"
	NodeTypeCodeBlock   = "codeBlock"
	NodeTypeHeading     = "heading"
	NodeTypeMediaGroup  = "mediaGroup"
	NodeTypeMediaSingle = "mediaSingle"
	NodeTypeOrderedList = "orderedList"
	NodeTypePanel       = "panel"
	NodeTypeParagraph   = "paragraph"
	NodeTypeRule        = "rule"
	NodeTypeTable       = "table"
	NodeTypeListItem    = "listItem"
	NodeTypeMedia       = "media"
	NodeTypeTableCell   = "table_cell"
	NodeTypeTableHeader = "table_header"
	NodeTypeTableRow    = "table_row"
	NodeTypeEmoji       = "emoji"
	NodeTypeHardBreak   = "hardBreak"
	NodeTypeInlineCard  = "inlineCard"
	NodeTypeMention     = "mention"
	NodeTypeText        = "text"
)

func inlineType(t NodeType) bool {
	switch t {
	case NodeTypeNone, NodeTypeEmoji, NodeTypeHardBreak, NodeTypeInlineCard, NodeTypeMention, NodeTypeText:
		return true
	default:
		return false
	}
}

type Layout string

// Enum values for Layout in Attributes struct
const (
	LayoutWrapLeft   = "wrap-left"
	LayoutCenter     = "center"
	LayoutWrapRight  = "wrap-right"
	LayoutWide       = "wide"
	LayoutFullWidth  = "full-width"
	LayoutAlignStart = "align-start"
	LayoutAlignEnd   = "align-end"
)

type blockNodeStack struct {
	data          []*Node
	ignoreBlocks  bool
	ignoredBlocks []*Node
}

func (s *blockNodeStack) PushContent(node *Node) {
	s.PeekBlockNode().AddContent(node)
}

func (s *blockNodeStack) PushBlockNode(node *Node) {
	if s.ignoreBlocks {
		s.ignoredBlocks = append(s.ignoredBlocks, node)

		// Paragraphs are the only block node type that can still be added
		if node.Type != NodeTypeParagraph {
			return
		}
	}

	// Update the actual document
	s.PushContent(node)
	// Update the context stack
	s.data = append(s.data, node)
}

// Intentionally unsafe because we should never peek an empty stack
func (s *blockNodeStack) PeekBlockNode() *Node {
	return s.data[len(s.data)-1]
}

// Intentionally unsafe because we should never pop an empty stack
func (s *blockNodeStack) PopBlockNode() *Node {
	last := len(s.data) - 1
	node := s.data[last]

	if s.ignoreBlocks {
		s.ignoredBlocks = s.ignoredBlocks[:len(s.ignoredBlocks)-1]
		if len(s.ignoredBlocks) == 0 {
			s.ignoreBlocks = false
		} else if node.Type != NodeTypeParagraph {
			return node
		}
	}

	s.data = s.data[:last]
	return node
}

func (s *blockNodeStack) IgnoreNestedBlocks(node *Node) {
	if s.ignoreBlocks {
		return
	}

	s.ignoreBlocks = true
	s.ignoredBlocks = append(s.ignoredBlocks, node)
}

// Mark represents a text formatting directive
type Mark string

// Enum values for Mark text formatting
const (
	MarkCode      Mark = "code"
	MarkEm        Mark = "em"
	MarkLink      Mark = "link"
	MarkStrike    Mark = "strike"
	MarkStrong    Mark = "strong"
	MarkSubsup    Mark = "subsup"
	MarkTextcolor Mark = "textColor"
	MarkUnderline Mark = "underline"
)

func NewRenderer() *JSONRenderer {
	root := Node{
		Version: 1,
		Type:    "doc",
	}
	return &JSONRenderer{
		document: &root,
		context: blockNodeStack{
			data: []*Node{&root},
		},
	}
}

func Render(w io.Writer, source []byte) error {
	gm := goldmark.New(
		goldmark.WithExtensions(
			extension.GFM, // GitHub flavoured markdown.
		),
		goldmark.WithParserOptions(
			parser.WithAttribute(), // Enables # headers {#custom-ids}.
		),
		goldmark.WithRenderer(NewRenderer()),
	)

	return gm.Convert(source, w)
}

func astToJSONType(node ast.Node) NodeType {
	switch n := node.(type) {
	case *ast.Document:
	case *ast.Paragraph,
		*ast.TextBlock:
		return NodeTypeParagraph
	case *ast.Heading:
		return NodeTypeHeading
	case *ast.Text,
		*ast.String,
		*extAst.Strikethrough,
		*ast.Emphasis,
		*ast.CodeSpan,
		*ast.Link:
		return NodeTypeText
	case *ast.CodeBlock,
		*ast.FencedCodeBlock:
		return NodeTypeCodeBlock
	case *ast.ThematicBreak:
		return NodeTypeRule
	case *ast.Blockquote:
		return NodeTypeBlockquote
	case *ast.List:
		if n.IsOrdered() {
			return NodeTypeOrderedList
		}
		return NodeTypeBulletList
	case *ast.ListItem:
		return NodeTypeListItem
	case *ast.Image:
		return NodeTypeMedia
	case *ast.HTMLBlock:
	case *ast.RawHTML:
	case *extAst.Table:
		return NodeTypeTable
	case *extAst.TableHeader:
		return NodeTypeTableHeader
	case *extAst.TableRow:
		return NodeTypeTableRow
	case *extAst.TableCell:
		return NodeTypeTableCell
	}

	return NodeTypeNone
}

func (r *JSONRenderer) walkNode(source []byte, node ast.Node, entering bool) ast.WalkStatus {
	//fmt.Printf("Node: %s, entering: %v, value: %q, children: %d\n", reflect.TypeOf(node).String(), entering, string(node.Text(source)), node.ChildCount())

	if !entering {
		if !inlineType(astToJSONType(node)) {
			r.context.PopBlockNode()
		}
		return ast.WalkContinue
	}

	jsonNode := &Node{Type: astToJSONType(node)}

	switch n := node.(type) {
	case *ast.Document:

	case *ast.Paragraph,
		*ast.TextBlock, // Untested
		*ast.List,
		*ast.ListItem,
		*ast.ThematicBreak,
		*ast.CodeBlock: // Untested
		r.context.PushBlockNode(jsonNode)

	case *ast.Blockquote:
		r.context.PushBlockNode(jsonNode)
		r.context.IgnoreNestedBlocks(jsonNode)

	case *ast.Heading:
		jsonNode.Attributes = &Attributes{
			Level: n.Level,
		}
		jsonNode.Text = string(node.Text(source))
		r.context.PushBlockNode(jsonNode)

	case *ast.Text:
		jsonNode.Text = string(n.Text(source))
		if len(jsonNode.Text) == 0 {
			// TODO: Uh what's happening here? Not sure why goldmark is splitting up paragraph text in this way.
			jsonNode.Text = " "
		}
		if len(r.context.data[len(r.context.data)-1].Text) > 0 { //&& r.context.data[len(r.context.data)-1].Type == "heading" {

		} else {
			r.context.PushContent(jsonNode)
		}

		if n.HardLineBreak() {
			lineBreak := &Node{Type: NodeTypeHardBreak}
			r.context.PushContent(lineBreak)
		}

	case *ast.String: // Untested
		jsonNode.Text = string(n.Text(source))
		if len(jsonNode.Text) == 0 {
			// TODO: Uh what's happening here? Not sure why goldmark is splitting up paragraph text in this way.
			jsonNode.Text = " "
		}
		r.context.PushContent(jsonNode)

	case *ast.CodeSpan:
		jsonNode.Text = string(n.Text(source))
		jsonNode.Marks = []MarkStruct{{Type: MarkCode}}
		r.context.PushContent(jsonNode)
		return ast.WalkSkipChildren

	case *extAst.Strikethrough:
		jsonNode.Text = string(n.Text(source))
		jsonNode.Marks = []MarkStruct{{Type: MarkStrike}}
		r.context.PushContent(jsonNode)
		return ast.WalkSkipChildren

	case *ast.Emphasis:
		jsonNode.Text = string(n.Text(source))
		if n.Level == 1 {
			jsonNode.Marks = []MarkStruct{{Type: MarkEm}}
		} else if n.Level >= 2 {
			jsonNode.Marks = []MarkStruct{{Type: MarkStrong}}
		}
		r.context.PushContent(jsonNode)
		return ast.WalkSkipChildren

	case *ast.Link:
		jsonNode.Text = string(n.Text(source))
		jsonNode.Marks = []MarkStruct{{
			Type: MarkLink,
			Attributes: &MarkAttributes{
				Href:  string(n.Destination),
				Title: string(n.Title),
			},
		}}
		r.context.PushContent(jsonNode)
		return ast.WalkSkipChildren

	case *ast.AutoLink:
		jsonNode.Type = NodeTypeText
		jsonNode.Text = string(n.URL(source))
		jsonNode.Marks = []MarkStruct{{
			Type: MarkLink,
			Attributes: &MarkAttributes{
				Href: string(n.URL(source)),
			},
		}}
		r.context.PushContent(jsonNode)
		return ast.WalkSkipChildren

	case *ast.Image:
		// if entering {
		// 	children := r.renderChildren(source, n)
		// 	r.image(tnode.Destination, tnode.Title, children)
		// }
		// return ast.WalkSkipChildren

	case *ast.FencedCodeBlock:
		jsonNode.Attributes = &Attributes{
			Language: string(n.Language(source)),
		}
		var content string
		lines := n.Lines()
		for i := 0; i < lines.Len(); i++ {
			segment := lines.At(i)
			content += string(segment.Value(source))
		}
		jsonNode.AddContent(&Node{
			Type: NodeTypeText,
			Text: content,
		})
		r.context.PushBlockNode(jsonNode)
		return ast.WalkSkipChildren

	case *ast.HTMLBlock:
		// if entering {
		// 	r.blockHtml(tnode, source)
		// }
	case *ast.RawHTML:
		// if entering {
		// 	r.rawHtml(tnode, source)
		// }
		// return ast.WalkSkipChildren
	case *extAst.Table:
		// r.table(tnode, entering)
	case *extAst.TableHeader:
		// if entering {
		// 	r.tableIsHeader = true
		// }
	case *extAst.TableRow:
		// if entering {
		// 	r.tableIsHeader = false
		// }
	case *extAst.TableCell:
		// if entering {
		// 	children := r.renderChildren(source, n)
		// 	if r.tableIsHeader {
		// 		r.tableHeaderCell(children, tnode.Alignment)
		// 	} else {
		// 		r.tableCell(children)
		// 	}
		// }
		// return ast.WalkSkipChildren
	default:
		panic("unknown type " + n.Kind().String())
	}

	return ast.WalkContinue
}

// Render implements goldmark.Renderer interface.
func (r *JSONRenderer) Render(w io.Writer, source []byte, n ast.Node) error {
	for current := n.FirstChild(); current != nil; current = current.NextSibling() {
		err := ast.Walk(current, func(current ast.Node, entering bool) (ast.WalkStatus, error) {
			return r.walkNode(source, current, entering), nil
		})
		if err != nil {
			return err
		}
	}
	vulns, err := docToCve(r.document)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(vulns, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func (*JSONRenderer) AddOptions(...renderer.Option) {
}

type Content struct {
	Description     string    `json:"description,omitempty"`
	ComponentName   string    `json:"component_name,omitempty"`
	AffectedVersion []Version `json:"affected_version,omitempty"`
	FixedVersion    []Version `json:"fixed_version,omitempty"`
	Cvss            string    `json:"cvss,omitempty"`
}

func docToCve(document *Node) (*Content, error) {
	affectedVersion := make([]Version, 0)
	fixedVersion := make([]Version, 0)
	var description strings.Builder
	var parseAffected, parseFixed bool
	var compName string

	for _, n := range document.Content {
		switch n.Type {
		case NodeTypeParagraph:
			for _, c := range n.Content {
				if strings.Contains(strings.ToLower(c.Text), "affected versions") {
					if len(n.Content) > 1 {
						affectedVersion = extractAffectedVersions(n)
						continue
					} else {
						parseAffected = true
						continue
					}
				}
				if strings.Contains(strings.ToLower(c.Text), "fixed versions") {
					if len(n.Content) > 1 {
						fixedVersion = extractFixedVersions(n)
						continue
					} else {
						parseFixed = true
						continue
					}
				}
				description.WriteString(c.Text)
			}
		case NodeTypeHeading:
			if strings.Contains(strings.ToLower(n.Text), "affected versions") && len(affectedVersion) == 0 {
				parseAffected = true
				continue
			}
			if strings.Contains(strings.ToLower(n.Text), "fixed versions") && len(fixedVersion) == 0 {
				parseFixed = true
				continue
			}
			description.WriteString(n.Text)
		case NodeTypeBulletList:
			if parseAffected {
				for _, c := range n.Content {
					for _, t := range c.Content {
						subAffectedVersion, cname := extractAffectedVersionsList(t)
						affectedVersion = append(affectedVersion, subAffectedVersion...)
						if len(compName) == 0 {
							compName = cname
						}
					}
				}
				parseAffected = false
			}
			if parseFixed {
				for _, c := range n.Content {
					for _, t := range c.Content {
						subFixedVersion := extractFixedVersionsList(t)
						fixedVersion = append(fixedVersion, subFixedVersion...)
					}
				}
				parseFixed = false
			}
			description.WriteString(n.Text)
		}
	}
	splittedCompName := strings.Split(compName, " ")
	if len(splittedCompName) == 2 {
		compName = strings.TrimSpace(splittedCompName[1])
	}
	desc := description.String()
	adi := addionalDataFromDescription(desc)
	if len(compName) == 0 {
		compName = adi.Component
	}
	return &Content{
		Description:     description.String(),
		AffectedVersion: affectedVersion,
		FixedVersion:    fixedVersion,
		ComponentName:   fmt.Sprintf("%s/%s", upstreamRepo, compName),
		Cvss:            adi.Cvss,
	}, nil
}

type Version struct {
	From  string `json:"from,omitempty"`
	To    string `json:"to,omitempty"`
	Fixed string `json:"fixed,omitempty"`
}

func extractAffectedVersions(node *Node) []Version {
	versions := make([]Version, 0)
	if len(node.Content) > 3 {
		for i := 3; i < len(node.Content); i = i + 2 {
			from := node.Content[i-1].Text
			to := node.Content[i].Text
			v := Version{
				From: sanitizeVersion(from),
				To:   sanitizeVersion(to),
			}
			versions = append(versions, v)
		}
	}
	return versions
}

func extractAffectedVersionsList(node *Node) ([]Version, string) {
	versions := make([]Version, 0)
	var compName string
	if len(node.Content) > 1 {
		for i := 1; i < len(node.Content); i = i + 2 {
			var from, to string
			compName, from = extractNameVersion(node.Content[i-1].Text)
			v := Version{}
			if _, err := version.Parse(from); err == nil {
				v.From = sanitizeVersion(from)
			}
			_, to = extractNameVersion(node.Content[i].Text)
			sanitazedTo := sanitizeVersion(to)
			if len(v.From) == 0 {
				v.From = sanitazedTo
			}
			v.To = sanitazedTo
			versions = append(versions, v)
		}
	}
	return versions, compName
}

func extractFixedVersionsList(node *Node) []Version {
	versions := make([]Version, 0)
	if len(node.Content) > 0 {
		for i := 0; i < len(node.Content); i++ {
			var fixed string
			_, fixed = extractNameVersion(node.Content[i].Text)
			fixed = sanitizeVersion(fixed)
			if _, err := version.Parse(fixed); err == nil {
				v := Version{
					Fixed: sanitizeVersion(fixed),
				}
				versions = append(versions, v)
			}
		}
	}
	return versions
}

func extractFixedVersions(node *Node) []Version {
	versions := make([]Version, 0)

	if len(node.Content) > 2 {
		for i := 2; i < len(node.Content); i++ {
			fixed := sanitizeVersion(node.Content[i].Text)
			v := Version{
				Fixed: sanitizeVersion(fixed),
			}
			versions = append(versions, v)
		}
	}
	return versions
}

func sanitizeVersion(version string) string {
	if version == "<=" {
		return "0.0.0"
	}
	if version == ">=" {
		return "2.0.0"
	}
	return trimString(version, []string{"v", "V"})
}

func extractNameVersion(nameVersion string) (string, string) {
	if strings.Contains(nameVersion, "<=") {
		nameVersionParts := strings.Split(nameVersion, "<=")
		return strings.TrimSpace(nameVersionParts[0]), "0.0.0"
	}
	if strings.Contains(nameVersion, "<") {
		nameVersionParts := strings.Split(nameVersion, "<")
		return strings.TrimSpace(nameVersionParts[0]), "0.0.0"
	}
	pattern := `^(?P<name>[^\s]+)\s+v(?P<version>\d+\.\d+\.\d+)`

	// Compile the regex pattern
	regex := regexp.MustCompile(pattern)

	// Find the matches in the string
	matches := regex.FindStringSubmatch(nameVersion)

	// Extract the captured groups
	if len(matches) < 3 {
		return "", nameVersion
	}
	return matches[1], matches[2]
}

func addionalDataFromDescription(description string) AdditionalFields {
	cvss := lookForCvssInDesc(description)
	component := lookForComponentInDesc(description, []string{
		"kube-controller-manager",
		"kubelet",
		"etcd",
		"kube-apiserver",
	},
	)
	return AdditionalFields{
		Cvss:      cvss,
		Component: component,
	}
}

type AdditionalFields struct {
	Cvss      string
	Score     string
	Component string
}

func lookForComponentInDesc(description string, coreCompArr []string) string {
	compIndex := strings.Index(description, "This bug affects")
	if compIndex != -1 {
		splittedComp := strings.Split(description[compIndex:], ".")
		if len(splittedComp) > 0 {
			return strings.ToLower(strings.ReplaceAll(splittedComp[0], "This bug affects ", ""))
		}
	}
	for _, c := range coreCompArr {
		if strings.Contains(strings.ToLower(description), c) {
			return c
		}
	}
	return ""
}
func lookForCvssInDesc(description string) string {
	cvssIndex := strings.Index(description, "CVSS:")
	if cvssIndex != -1 {
		splittedCvss := strings.Split(description[cvssIndex:], " ")
		if len(splittedCvss) > 0 {
			return strings.Trim(splittedCvss[0], ")")
		}
	}
	return ""
}
