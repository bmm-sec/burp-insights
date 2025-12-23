package burp

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type IssueReference struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

type IssueDefinition struct {
	TypeIndex                    uint32           `json:"typeIndex"`
	Name                         string           `json:"name"`
	Description                  string           `json:"description,omitempty"`
	Remediation                  string           `json:"remediation,omitempty"`
	WebIntro                     string           `json:"webIntro,omitempty"`
	TypicalSeverity              string           `json:"typicalSeverity,omitempty"`
	References                   []IssueReference `json:"references,omitempty"`
	VulnerabilityClassifications []IssueReference `json:"vulnerabilityClassifications,omitempty"`
}

type IssueDefinitionsExport struct {
	Count       int               `json:"count,omitempty"`
	Definitions []IssueDefinition `json:"definitions"`
}

var issueDefinitions struct {
	mu   sync.RWMutex
	defs map[uint32]IssueDefinition
}

// LoadIssueDefinitionsFromJar loads Burp issue definitions from a Burp Suite jar file.
func LoadIssueDefinitionsFromJar(jarPath string) error {
	if strings.TrimSpace(jarPath) == "" {
		return errors.New("jar path is empty")
	}

	info, err := os.Stat(jarPath)
	if err != nil {
		return fmt.Errorf("stat jar: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("jar path is a directory: %s", jarPath)
	}

	zr, err := zip.OpenReader(jarPath)
	if err != nil {
		return fmt.Errorf("open jar: %w", err)
	}
	defer zr.Close()

	defs := make(map[uint32]IssueDefinition)
	for _, f := range zr.File {
		if !strings.HasPrefix(f.Name, "resources/KnowledgeBase/Issues/") {
			continue
		}
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}

		var def IssueDefinition
		dec := json.NewDecoder(rc)
		if err := dec.Decode(&def); err != nil {
			rc.Close()
			continue
		}
		rc.Close()

		if def.TypeIndex == 0 || def.Name == "" {
			continue
		}
		defs[def.TypeIndex] = def
	}

	return loadIssueDefinitionsMap(defs, fmt.Sprintf("no issue definitions found in jar: %s", jarPath))
}

// LoadIssueDefinitionsFromJSON loads issue definitions from a JSON blob containing either
// a list of definitions or an export object with a definitions array.
func LoadIssueDefinitionsFromJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return errors.New("issue definitions JSON is empty")
	}

	var defs []IssueDefinition
	if err := json.Unmarshal(data, &defs); err == nil {
		return loadIssueDefinitionsSlice(defs, "no issue definitions found in JSON array")
	}

	var export IssueDefinitionsExport
	if err := json.Unmarshal(data, &export); err != nil {
		return fmt.Errorf("parse issue definitions JSON: %w", err)
	}

	return loadIssueDefinitionsSlice(export.Definitions, "no issue definitions found in JSON export")
}

// IssueDefinitions returns the loaded issue definitions sorted by type index.
func IssueDefinitions() []IssueDefinition {
	issueDefinitions.mu.RLock()
	defer issueDefinitions.mu.RUnlock()

	defs := make([]IssueDefinition, 0, len(issueDefinitions.defs))
	for _, def := range issueDefinitions.defs {
		defs = append(defs, def)
	}
	sort.Slice(defs, func(i, j int) bool {
		return defs[i].TypeIndex < defs[j].TypeIndex
	})
	return defs
}

// IssueDefinitionForType returns the loaded issue definition for the given type ID.
func IssueDefinitionForType(typeID uint32) (IssueDefinition, bool) {
	issueDefinitions.mu.RLock()
	defer issueDefinitions.mu.RUnlock()

	if issueDefinitions.defs == nil {
		return IssueDefinition{}, false
	}
	def, ok := issueDefinitions.defs[typeID]
	return def, ok
}

func loadIssueDefinitionsSlice(defs []IssueDefinition, emptyErr string) error {
	defMap := make(map[uint32]IssueDefinition)
	for _, def := range defs {
		if def.TypeIndex == 0 || def.Name == "" {
			continue
		}
		defMap[def.TypeIndex] = def
	}

	return loadIssueDefinitionsMap(defMap, emptyErr)
}

func loadIssueDefinitionsMap(defs map[uint32]IssueDefinition, emptyErr string) error {
	if len(defs) == 0 {
		return errors.New(emptyErr)
	}

	issueDefinitions.mu.Lock()
	issueDefinitions.defs = defs
	issueDefinitions.mu.Unlock()
	return nil
}

// FindDefaultBurpJar attempts to locate a Burp Suite jar in common install paths.
func FindDefaultBurpJar() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	candidates := []string{
		filepath.Join(home, "BurpSuitePro", "burpsuite_pro.jar"),
		filepath.Join(home, "BurpSuiteCommunity", "burpsuite_community.jar"),
		"/opt/BurpSuitePro/burpsuite_pro.jar",
		"/opt/BurpSuiteCommunity/burpsuite_community.jar",
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return "", errors.New("burp suite jar not found in default locations")
}
