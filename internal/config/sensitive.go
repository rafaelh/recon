package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"go.yaml.in/yaml/v3"
)

// SensitivePath is one entry of the sensitive-path list: a path to request and
// what a response must look like for it to be an exposure. A catch-all site
// that answers 200 to everything matches nothing, because every entry needs a
// Signature (an RE2 over the body, at most 1 MiB) or Magic (a body prefix).
type SensitivePath struct {
	Path      string
	Signature string // RE2; empty if Magic is used alone
	Magic     []byte // body prefix; empty if Signature is used alone
	Status    int    // default 200
	Severity  string // high, medium or low; default medium
}

// Hash is a short stable identifier of what the entry checks for. A hit
// records it, so a changed signature, magic or status is a different check.
func (p SensitivePath) Hash() string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%x\x00%d", p.Signature, p.Magic, p.Status)))
	return hex.EncodeToString(sum[:4])
}

// Describe is the signature recorded with a hit.
func (p SensitivePath) Describe() string {
	var parts []string
	if p.Signature != "" {
		parts = append(parts, p.Signature)
	}
	if len(p.Magic) > 0 {
		parts = append(parts, "magic:"+hex.EncodeToString(p.Magic))
	}
	return strings.Join(parts, " + ")
}

var compiled sync.Map // signature -> *regexp.Regexp

func signatureRE(sig string) *regexp.Regexp {
	if re, ok := compiled.Load(sig); ok {
		return re.(*regexp.Regexp)
	}
	re, err := regexp.Compile(sig)
	if err != nil {
		return nil
	}
	compiled.Store(sig, re)
	return re
}

// Match reports whether a response is this entry's exposure and, if so, the
// signature to record. Every condition the entry gives must hold.
func (p SensitivePath) Match(status int, body []byte) (string, bool) {
	if status != p.Status {
		return "", false
	}
	if len(p.Magic) > 0 && !bytes.HasPrefix(body, p.Magic) {
		return "", false
	}
	if p.Signature != "" {
		re := signatureRE(p.Signature)
		if re == nil || !re.Match(body) {
			return "", false
		}
	}
	if p.Signature == "" && len(p.Magic) == 0 {
		return "", false
	}
	return p.Describe(), true
}

var sensitiveFields = map[string]bool{"path": true, "signature": true, "magic": true, "status": true, "severity": true}

// parseSensitivePaths reads a YAML list of {path, signature and/or magic,
// status, severity}. A plain string, an entry with neither signature nor magic
// and an unknown field are errors. Each path is appended to a service's origin,
// so it must be an absolute path.
func parseSensitivePaths(b []byte) ([]SensitivePath, error) {
	var nodes []yaml.Node
	if err := yaml.Unmarshal(b, &nodes); err != nil {
		return nil, fmt.Errorf("not a valid YAML list: %w", err)
	}
	var out []SensitivePath
	for i, n := range nodes {
		if n.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("entry %d (%q) is not a mapping: each entry needs a path and a signature or magic", i+1, strings.TrimSpace(n.Value))
		}
		for j := 0; j+1 < len(n.Content); j += 2 {
			if k := n.Content[j].Value; !sensitiveFields[k] {
				return nil, fmt.Errorf("entry %d: unknown field %q", i+1, k)
			}
		}
		var raw struct {
			Path      string `yaml:"path"`
			Signature string `yaml:"signature"`
			Magic     *string
			Status    int    `yaml:"status"`
			Severity  string `yaml:"severity"`
		}
		if err := n.Decode(&raw); err != nil {
			return nil, fmt.Errorf("entry %d: %w", i+1, err)
		}
		p := SensitivePath{Path: raw.Path, Signature: raw.Signature, Status: raw.Status, Severity: raw.Severity}
		if _, err := url.ParseRequestURI(p.Path); err != nil || !strings.HasPrefix(p.Path, "/") {
			return nil, fmt.Errorf("entry %q is not a path starting with /", p.Path)
		}
		if p.Status == 0 {
			p.Status = 200
		}
		if p.Status < 100 || p.Status > 599 {
			return nil, fmt.Errorf("entry %q: status %d is not an HTTP status", p.Path, p.Status)
		}
		switch p.Severity {
		case "":
			p.Severity = "medium"
		case "high", "medium", "low":
		default:
			return nil, fmt.Errorf("entry %q: severity %q is not high, medium or low", p.Path, p.Severity)
		}
		if p.Signature != "" {
			if _, err := regexp.Compile(p.Signature); err != nil {
				return nil, fmt.Errorf("entry %q: signature %q: %w", p.Path, p.Signature, err)
			}
		}
		if raw.Magic != nil {
			m, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(*raw.Magic), " ", ""))
			if err != nil || len(m) == 0 {
				return nil, fmt.Errorf("entry %q: magic %q is not a hex byte prefix", p.Path, *raw.Magic)
			}
			p.Magic = m
		}
		if p.Signature == "" && len(p.Magic) == 0 {
			return nil, fmt.Errorf("entry %q has neither a signature nor magic; every entry needs one so a catch-all 200 is not flagged", p.Path)
		}
		out = append(out, p)
	}
	return out, nil
}
