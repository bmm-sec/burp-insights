package burp

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func withIssueDefinitions(t *testing.T, defs map[uint32]IssueDefinition) {
	t.Helper()
	issueDefinitions.mu.Lock()
	orig := issueDefinitions.defs
	issueDefinitions.defs = defs
	issueDefinitions.mu.Unlock()

	t.Cleanup(func() {
		issueDefinitions.mu.Lock()
		issueDefinitions.defs = orig
		issueDefinitions.mu.Unlock()
	})
}

func TestLoadIssueDefinitionsFromJSON(t *testing.T) {
	withIssueDefinitions(t, nil)

	defs := []IssueDefinition{{TypeIndex: 1, Name: "Test"}, {TypeIndex: 2, Name: "Another"}}
	data, _ := json.Marshal(defs)
	if err := LoadIssueDefinitionsFromJSON(data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := IssueDefinitions(); len(got) != 2 {
		t.Fatalf("expected 2 defs, got %d", len(got))
	}
	if _, ok := IssueDefinitionForType(1); !ok {
		t.Fatal("expected type 1 definition")
	}
}

func TestLoadIssueDefinitionsFromJSONExport(t *testing.T) {
	withIssueDefinitions(t, nil)

	export := IssueDefinitionsExport{Definitions: []IssueDefinition{{TypeIndex: 10, Name: "Exported"}}}
	data, _ := json.Marshal(export)
	if err := LoadIssueDefinitionsFromJSON(data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := IssueDefinitionForType(10); !ok {
		t.Fatal("expected type 10 definition")
	}
}

func TestLoadIssueDefinitionsFromJSONEmpty(t *testing.T) {
	withIssueDefinitions(t, nil)
	if err := LoadIssueDefinitionsFromJSON([]byte(" ")); err == nil {
		t.Fatal("expected error for empty json")
	}
}

func TestLoadIssueDefinitionsFromJar(t *testing.T) {
	withIssueDefinitions(t, nil)

	tmpDir := t.TempDir()
	jarPath := filepath.Join(tmpDir, "defs.jar")
	f, err := os.Create(jarPath)
	if err != nil {
		t.Fatalf("create jar: %v", err)
	}
	zw := zip.NewWriter(f)

	def := IssueDefinition{TypeIndex: 55, Name: "JarDef"}
	defBytes, _ := json.Marshal(def)
	w, err := zw.Create("resources/KnowledgeBase/Issues/issue.json")
	if err != nil {
		t.Fatalf("create zip entry: %v", err)
	}
	if _, err := w.Write(defBytes); err != nil {
		t.Fatalf("write zip entry: %v", err)
	}

	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close jar: %v", err)
	}

	if err := LoadIssueDefinitionsFromJar(jarPath); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := IssueDefinitionForType(55); !ok {
		t.Fatal("expected type 55 definition")
	}
}

func TestLoadIssueDefinitionsFromJarErrors(t *testing.T) {
	withIssueDefinitions(t, nil)

	if err := LoadIssueDefinitionsFromJar(""); err == nil {
		t.Fatal("expected error for empty path")
	}

	dir := t.TempDir()
	if err := LoadIssueDefinitionsFromJar(dir); err == nil {
		t.Fatal("expected error for directory path")
	}

	jarPath := filepath.Join(dir, "empty.jar")
	f, err := os.Create(jarPath)
	if err != nil {
		t.Fatalf("create jar: %v", err)
	}
	zw := zip.NewWriter(f)
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close jar: %v", err)
	}

	if err := LoadIssueDefinitionsFromJar(jarPath); err == nil {
		t.Fatal("expected error for empty jar")
	}
}

func TestLoadEmbeddedIssueDefinitions(t *testing.T) {
	withIssueDefinitions(t, nil)
	if err := LoadEmbeddedIssueDefinitions(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(IssueDefinitions()) == 0 {
		t.Fatal("expected embedded definitions to load")
	}
}

func TestFindDefaultBurpJar(t *testing.T) {
	origHome := os.Getenv("HOME")
	tmp := t.TempDir()
	if err := os.Setenv("HOME", tmp); err != nil {
		t.Fatalf("set HOME: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Setenv("HOME", origHome)
	})

	path := filepath.Join(tmp, "BurpSuitePro", "burpsuite_pro.jar")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte("jar"), 0o644); err != nil {
		t.Fatalf("write jar: %v", err)
	}

	found, err := FindDefaultBurpJar()
	if err != nil {
		t.Fatalf("expected jar to be found, got error %v", err)
	}
	if found != path {
		t.Fatalf("unexpected jar path: %q", found)
	}
}

func TestLoadIssueDefinitionsFromJSONWithInvalidData(t *testing.T) {
	withIssueDefinitions(t, nil)
	bad := []byte("not-json")
	if err := LoadIssueDefinitionsFromJSON(bad); err == nil {
		t.Fatal("expected error for invalid json")
	}

	data := bytes.TrimSpace([]byte("[]"))
	if err := LoadIssueDefinitionsFromJSON(data); err == nil {
		t.Fatal("expected error for empty definitions array")
	}
}
