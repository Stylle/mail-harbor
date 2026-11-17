package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMissingKeyNeverRekeysExistingDatabase(t *testing.T) {
	dir := t.TempDir()
	s, e := openStore(dir)
	if e != nil {
		t.Fatal(e)
	}
	s.db.Close()
	before, e := os.ReadFile(filepath.Join(dir, "mail-harbor.db"))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(filepath.Join(dir, "master.key")); e != nil {
		t.Fatal(e)
	}
	if _, e = openStore(dir); e == nil || !strings.Contains(e.Error(), "no replacement key") {
		t.Fatal("missing existing key was not diagnosed safely")
	}
	if _, e = os.Stat(filepath.Join(dir, "master.key")); !os.IsNotExist(e) {
		t.Fatal("replacement key was generated")
	}
	after, e := os.ReadFile(filepath.Join(dir, "mail-harbor.db"))
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("database changed despite missing key")
	}
}

func TestBadKeyLengthAndWrongPathTypesArePreserved(t *testing.T) {
	for _, length := range []int{0, 16, 31, 33, 100} {
		t.Run(string(rune('A'+length)), func(t *testing.T) {
			dir := t.TempDir()
			key := bytes.Repeat([]byte{7}, length)
			p := filepath.Join(dir, "master.key")
			if e := os.WriteFile(p, key, 0600); e != nil {
				t.Fatal(e)
			}
			if _, e := openStore(dir); e == nil || !strings.Contains(e.Error(), "invalid length") {
				t.Fatal("bad key was not diagnosed")
			}
			after, _ := os.ReadFile(p)
			if !bytes.Equal(after, key) {
				t.Fatal("invalid key overwritten")
			}
			if _, e := os.Stat(filepath.Join(dir, "mail-harbor.db")); !os.IsNotExist(e) {
				t.Fatal("database created for invalid key")
			}
		})
	}
	dir := t.TempDir()
	if e := os.Mkdir(filepath.Join(dir, "master.key"), 0700); e != nil {
		t.Fatal(e)
	}
	if _, e := openStore(dir); e == nil || !strings.Contains(e.Error(), "regular file") {
		t.Fatal("directory-as-key was not diagnosed")
	}
}

func TestExistingKeyAndEncryptedSecurityStateSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	s, e := openStore(dir)
	if e != nil {
		t.Fatal(e)
	}
	key, _ := os.ReadFile(filepath.Join(dir, "master.key"))
	encrypted := s.encrypt("synthetic secret")
	if e = s.update(func(st *State) error { st.TOTPSecret = encrypted; return nil }); e != nil {
		t.Fatal(e)
	}
	s.db.Close()
	s, e = openStore(dir)
	if e != nil {
		t.Fatal(e)
	}
	s.db.Close()
	after, _ := os.ReadFile(filepath.Join(dir, "master.key"))
	if !bytes.Equal(key, after) {
		t.Fatal("valid key replaced")
	}
	if e = os.WriteFile(filepath.Join(dir, "master.key"), bytes.Repeat([]byte{9}, 32), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = openStore(dir); e == nil || !strings.Contains(e.Error(), "does not match database") {
		t.Fatal("wrong key accepted for account-free encrypted 2FA state")
	}
}
