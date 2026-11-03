package store_test

import "os"

func writeGarbage(p string) error {
	return os.WriteFile(p, []byte("this is definitely not a sqlite database file, just text padding padding padding padding"), 0o600)
}
