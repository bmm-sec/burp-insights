package burp

import (
	_ "embed"
	"errors"
)

//go:embed issue_definitions_embedded.json
var embeddedIssueDefinitions []byte

// LoadEmbeddedIssueDefinitions loads issue definitions bundled with the binary.
func LoadEmbeddedIssueDefinitions() error {
	if len(embeddedIssueDefinitions) == 0 {
		return errors.New("embedded issue definitions are missing")
	}
	return LoadIssueDefinitionsFromJSON(embeddedIssueDefinitions)
}
