//go:build linux

// One-shot, network-isolated Compose initialization. Never starts an API and
// only adjusts ownership of the dedicated mount and four known SQLite/key files.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func prepare(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("data mount must be a directory, not a symlink")
	}
	// A nested bind mount can otherwise redirect a known file to another mount.
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(f)
	unescape := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\134`, `\`)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 4 && strings.HasPrefix(unescape.Replace(fields[4]), filepath.Clean(dir)+"/") {
			f.Close()
			return errors.New("nested mounts below data are not supported")
		}
	}
	err = scanner.Err()
	f.Close()
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	if etc, e := root.Stat("etc"); e == nil && etc.IsDir() {
		if usr, e := root.Stat("usr"); e == nil && usr.IsDir() {
			return errors.New("data mount appears to be a system directory; use a dedicated application folder")
		}
	}
	files := []*os.File{}
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	for _, name := range []string{".", "master.key", "mail-harbor.db", "mail-harbor.db-wal", "mail-harbor.db-shm"} {
		f, e := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return fmt.Errorf("inspect known data entry %s: %w", name, e)
		}
		files = append(files, f)
		st, e := f.Stat()
		if e != nil {
			return e
		}
		sys := st.Sys().(*syscall.Stat_t)
		if name != "." && (!st.Mode().IsRegular() || sys.Nlink != 1) {
			return errors.New("known data entries must be regular files without symlinks/hard links")
		}
		if sys.Dev != info.Sys().(*syscall.Stat_t).Dev {
			return errors.New("known data file is on a different mount")
		}
	}
	// All paths are checked before the first ownership change. File descriptors
	// keep path replacements from redirecting ownership to unrelated host files.
	for _, f := range files {
		st, e := f.Stat()
		if e != nil {
			return e
		}
		sys := st.Sys().(*syscall.Stat_t)
		if sys.Uid == 10001 && sys.Gid == 10001 {
			continue
		}
		if e = f.Chown(10001, 10001); e != nil {
			if errors.Is(e, syscall.EPERM) || errors.Is(e, syscall.EACCES) || errors.Is(e, syscall.EOPNOTSUPP) {
				log.Print("Mount disallows ownership changes; preserving its ACL/mode. Mail service will check actual write access.")
				continue
			}
			return e
		}
	}
	return nil
}

func main() {
	if os.Getuid() != 0 {
		log.Fatal("data-init runs only as the isolated setup container")
	}
	if err := prepare("/data"); err != nil {
		log.Fatal("Cannot prepare dedicated /data mount: ", err)
	}
}
