package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// B2, D13: permutations default on, cap 200; file, env and flag settings.
func TestPermutationSettings(t *testing.T) {
	clearEnv(t)
	s, err := load(t, "")
	if err != nil {
		t.Fatal(err)
	}
	if !s.Permutations.Enabled || s.Permutations.MaxPerSeed != 200 {
		t.Errorf("defaults = %+v", s.Permutations)
	}
	if len(s.WordlistWords) < 80 || s.WordlistHash == "" {
		t.Errorf("built-in wordlist: %d words, hash %q", len(s.WordlistWords), s.WordlistHash)
	}

	if s, err = load(t, "", "--no-permutations"); err != nil || s.Permutations.Enabled {
		t.Errorf("--no-permutations: %+v %v", s.Permutations, err)
	}
	if s, err = load(t, writeFile(t, "permutations:\n  enabled: false\n  max_per_seed: 7\n")); err != nil ||
		s.Permutations.Enabled || s.Permutations.MaxPerSeed != 7 {
		t.Errorf("file: %+v %v", s.Permutations, err)
	}
	t.Setenv("RECON_PERMUTATIONS_MAX_PER_SEED", "9")
	if s, err = load(t, writeFile(t, "permutations:\n  max_per_seed: 7\n")); err != nil || s.Permutations.MaxPerSeed != 9 {
		t.Errorf("env over file: %+v %v", s.Permutations, err)
	}
	if s, err = load(t, "", "--permutations-max", "11"); err != nil || s.Permutations.MaxPerSeed != 11 {
		t.Errorf("flag over env: %+v %v", s.Permutations, err)
	}
}

func TestPermutationValidation(t *testing.T) {
	clearEnv(t)
	for _, args := range [][]string{{"--permutations-max", "0"}, {"--permutations-max", "-3"}} {
		_, err := load(t, "", args...)
		if err == nil || !strings.Contains(err.Error(), "permutations.max_per_seed") {
			t.Errorf("%v: error %v should name permutations.max_per_seed", args, err)
		}
	}
}

// B2: a custom wordlist replaces the built-in one, and its content changes the hash.
func TestWordlistContentAndHash(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	a := filepath.Join(dir, "a.txt")
	b := filepath.Join(dir, "b.txt")
	os.WriteFile(a, []byte("# comment\nalpha\nbeta\n"), 0o600)
	os.WriteFile(b, []byte("alpha\nbeta\ngamma\n"), 0o600)
	sa, err := load(t, "", "--wordlist", a)
	if err != nil {
		t.Fatal(err)
	}
	sb, _ := load(t, "", "--wordlist", b)
	if strings.Join(sa.WordlistWords, ",") != "alpha,beta" {
		t.Errorf("words = %v", sa.WordlistWords)
	}
	if sa.WordlistHash == sb.WordlistHash {
		t.Error("different wordlists must have different hashes")
	}
}

func TestHelpShowsPermutationFlags(t *testing.T) {
	// Registered flags carry their defaults in the usage text (Spec 1 B21).
	fs := newFlagSetForHelp()
	for _, name := range []string{"no-permutations", "permutations-max"} {
		if fs.Lookup(name) == nil {
			t.Errorf("flag --%s missing", name)
		}
	}
	if f := fs.Lookup("permutations-max"); f != nil && f.DefValue != "200" {
		t.Errorf("--permutations-max default = %q", f.DefValue)
	}
}
