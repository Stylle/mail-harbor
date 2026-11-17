package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func storageError(action string, err error) error {
	if errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("%s: permission denied; the data mount must grant the container user read/write access (not a damaged key): %w", action, err)
	}
	return fmt.Errorf("%s: %w", action, err)
}

func regularDataPath(path string) error {
	st, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return storageError("inspect data file", err)
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("data file %s must be a regular file, not a directory or symlink", filepath.Base(path))
	}
	return nil
}

func readMasterKey(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 33))
}

func loadMasterKey(dir string) ([]byte, error) {
	path := filepath.Join(dir, "master.key")
	if err := regularDataPath(path); err != nil {
		return nil, err
	}
	key, err := readMasterKey(path)
	if os.IsNotExist(err) {
		// Missing keys on existing databases must never be replaced: other
		// encrypted fields (including 2FA) can exist without any mail accounts.
		for _, name := range []string{"mail-harbor.db", "mail-harbor.db-wal", "mail-harbor.db-shm"} {
			if _, e := os.Lstat(filepath.Join(dir, name)); e == nil {
				return nil, errors.New("master.key is missing beside an existing database; retain the current mount and restore its matching key/complete backup; no replacement key was generated")
			} else if !os.IsNotExist(e) {
				return nil, storageError("inspect existing database", e)
			}
		}
		key = make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return nil, err
		}
		// Never truncate an existing key if initialization races another process.
		f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if os.IsExist(e) {
			key, err = readMasterKey(path)
		} else {
			if e != nil {
				return nil, storageError("create master.key in data directory", e)
			}
			_, err = f.Write(key)
			if err == nil {
				err = f.Sync()
			}
			closeErr := f.Close()
			if err == nil {
				err = closeErr
			}
			if err != nil {
				return nil, storageError("persist new master.key", err)
			}
		}
	}
	if err != nil {
		return nil, storageError("read master.key", err)
	}
	if len(key) != 32 {
		return nil, errors.New("master.key has invalid length (expected 32 binary bytes); original file was preserved; restore the matching key/complete backup, do not replace it with a password or text file")
	}
	return key, nil
}
