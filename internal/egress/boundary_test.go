package egress_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// D13/B12: only internal/egress may import raw network or process packages.
func TestPassiveBoundaryImports(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(root)
		if parent == root {
			t.Fatal("go.mod not found")
		}
		root = parent
	}
	cmd := exec.Command("go", "list", "-json", "./...")
	cmd.Dir = root
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("go list: %v\n%s", err, errb.String())
	}
	forbidden := map[string]bool{
		"net": true, "net/http": true, "crypto/tls": true, "syscall": true, "os/exec": true,
		"github.com/miekg/dns": true,
	}
	dec := json.NewDecoder(&out)
	checked := 0
	for dec.More() {
		var p struct {
			ImportPath string
			Imports    []string
		}
		if err := dec.Decode(&p); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(p.ImportPath, "/internal/") && !strings.Contains(p.ImportPath, "/cmd/") {
			continue
		}
		checked++
		if strings.HasSuffix(p.ImportPath, "/internal/egress") || strings.Contains(p.ImportPath, "/internal/egress/") {
			continue
		}
		for _, imp := range p.Imports {
			if forbidden[imp] {
				t.Errorf("%s imports %s directly; route it through internal/egress", p.ImportPath, imp)
			}
		}
	}
	if checked < 5 {
		t.Errorf("boundary test only saw %d packages", checked)
	}
}
