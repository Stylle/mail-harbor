//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenStorePreservesExistingMountAndDatabaseModes(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0755); e != nil {
		t.Fatal(e)
	}
	s, e := openStore(dir)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.db.Close(); e != nil {
		t.Fatal(e)
	}
	db := filepath.Join(dir, "mail-harbor.db")
	if e = os.Chmod(db, 0640); e != nil {
		t.Fatal(e)
	}
	s, e = openStore(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.db.Close()
	for path, mode := range map[string]os.FileMode{dir: 0755, db: 0640} {
		st, e := os.Stat(path)
		if e != nil {
			t.Fatal(e)
		}
		if st.Mode().Perm() != mode {
			t.Fatal("existing host mode was changed")
		}
	}
	st, e := os.Stat(filepath.Join(dir, "master.key"))
	if e != nil {
		t.Fatal(e)
	}
	if st.Mode().Perm()&0077 != 0 {
		t.Fatal("new key is accessible to other users")
	}
}
