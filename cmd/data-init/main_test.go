//go:build linux

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPrepareTouchesOnlyKnownOwnershipAndRetainsBytesModes(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("one-shot initializer needs root")
	}
	dir := t.TempDir()
	if e := os.Chmod(dir, 0755); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"master.key", "mail-harbor.db", "unrelated"} {
		if e := os.WriteFile(filepath.Join(dir, name), []byte("synthetic fixture"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := prepare(dir); e != nil {
		t.Fatal(e)
	}
	if e := prepare(dir); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"master.key", "mail-harbor.db", "unrelated"} {
		st, e := os.Stat(filepath.Join(dir, name))
		if e != nil {
			t.Fatal(e)
		}
		want := uint32(10001)
		if name == "unrelated" {
			want = 0
		}
		if st.Sys().(*syscall.Stat_t).Uid != want || st.Mode().Perm() != 0600 {
			t.Fatal("unexpected file ownership/mode")
		}
		b, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil || string(b) != "synthetic fixture" {
			t.Fatal("file bytes changed")
		}
	}
	st, e := os.Stat(dir)
	if e != nil || st.Mode().Perm() != 0755 {
		t.Fatal("host directory mode changed")
	}
}

func TestPrepareRejectsLinkedAndSpecialFilesBeforeChangingOwnership(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("one-shot initializer needs root")
	}
	for _, kind := range []string{"symlink", "hardlink", "directory", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(t.TempDir(), "outside")
			if e := os.WriteFile(target, []byte("synthetic"), 0600); e != nil {
				t.Fatal(e)
			}
			name := filepath.Join(dir, "master.key")
			var e error
			switch kind {
			case "symlink":
				e = os.Symlink(target, name)
			case "hardlink":
				e = os.Link(target, name)
			case "directory":
				e = os.Mkdir(name, 0700)
			case "fifo":
				e = syscall.Mkfifo(name, 0600)
			}
			if e != nil {
				t.Fatal(e)
			}
			if prepare(dir) == nil {
				t.Fatal("unsafe path accepted")
			}
			st, _ := os.Stat(target)
			if st.Sys().(*syscall.Stat_t).Uid != 0 {
				t.Fatal("outside target ownership changed")
			}
		})
	}
}
