package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// writeJSON atomically writes v as indented JSON to path (temp + fsync +
// rename). The caller is responsible for fsyncing the parent directory.
func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// syncDir fsyncs a directory so a preceding rename/create is durable.
func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// linkBackup hard-links path to a timestamped sibling before it is replaced.
//
// A LINK, not a copy: the caller is about to replace path via rename(2), which
// swaps the directory entry and leaves the inode alone. So the link keeps
// pointing at the old inode with the old bytes, for free and with no window in
// which either file is incomplete. Copying would read a file that is about to
// be overwritten and could tear; linking cannot.
//
// The whole sequence the caller performs is:
//
//	link(db, db.<timestamp>)   atomic; the previous contents are now safe
//	write(db.tmp)              not atomic, and it does not matter -- nothing
//	                           reads db.tmp, and a crash here leaves both the
//	                           db and the backup intact
//	rename(db.tmp, db)         atomic; readers see old or new, never torn
//
// Deliberately not fsynced. These are a recovery convenience, not the
// authoritative record: the db write itself is synced and the directory is
// synced after it, so a backup that loses its metadata to a power cut costs
// nothing that was not already lost. Paying an fsync per backup on every
// mutation would be real cost for no real guarantee.
//
// A missing source is not an error -- that is the first write, when there is
// nothing to preserve.
func linkBackup(path string, now time.Time) (string, error) {
	// Nanosecond precision so a burst of mutations inside one second cannot
	// collide. If two links land on the same name anyway, the existing one is
	// from the same instant and is as good a backup as the one being made.
	name := path + ".bak." + now.UTC().Format("20060102T150405.000000000Z")
	err := os.Link(path, name)
	switch {
	case err == nil:
		return name, nil
	case os.IsNotExist(err):
		return "", nil // first write: nothing to back up
	case os.IsExist(err):
		return name, nil
	default:
		return "", err
	}
}

// pruneBackups keeps the newest keep backups of path and removes the rest.
//
// The timestamp format is fixed-width and zero-padded, so lexical order is
// chronological order and no parsing is needed -- one less thing to get wrong
// than comparing parsed times, and it cannot mis-sort a malformed name into
// the "keep" set.
func pruneBackups(path string, keep int) error {
	dir := filepath.Dir(path)
	prefix := filepath.Base(path) + ".bak."
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var backups []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), prefix) {
			backups = append(backups, e.Name())
		}
	}
	if len(backups) <= keep {
		return nil
	}
	slices.Sort(backups)
	for _, name := range backups[:len(backups)-keep] {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// latestBackup returns the newest backup of path, or "" when there is none.
// Lexical order is chronological because the timestamp is fixed-width.
func latestBackup(path string) (string, error) {
	dir := filepath.Dir(path)
	prefix := filepath.Base(path) + ".bak."
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	newest := ""
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), prefix) && e.Name() > newest {
			newest = e.Name()
		}
	}
	if newest == "" {
		return "", nil
	}
	return filepath.Join(dir, newest), nil
}
