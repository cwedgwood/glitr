package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestReadMetadataNeverReturnsAZeroBlockSize: ReadMetadataForDisk is a public
// API for tools holding only a backstore path, and its Volume carries a block
// size that could be 0.
//
// 0 is not a mismatch a caller can arbitrate with "the db wins" -- it is an
// absent value that looks like a real one, and it is not a legal block size.
// It arises two ways: a metadata.json written before the field existed, and a
// record whose block size startup repair backfilled into the db while leaving
// this file untouched.
func TestReadMetadataNeverReturnsAZeroBlockSize(t *testing.T) {
	dir := t.TempDir()
	disk := filepath.Join(dir, "disk")
	if err := os.WriteFile(disk, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// Exactly the shape written before the field existed.
	const legacy = `{"uuid":"11111111-1111-4111-8111-111111111111",
	                "wwn":"0000000000000000","capacity":1048576,"state":"ready"}`
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}

	v, err := ReadMetadataForDisk(disk)
	if err != nil {
		t.Fatal(err)
	}
	if v.BlockSize == 0 {
		t.Fatal("a caller reading .BlockSize directly gets 0, which is not a legal " +
			"block size and cannot be told apart from a real geometry")
	}
	if v.BlockSize != DefaultBlockSize {
		t.Errorf("an absent block size must resolve to %d -- what these volumes' "+
			"initiators have always seen, since they were created at the kernel's "+
			"fileio default -- got %d", DefaultBlockSize, v.BlockSize)
	}
}

// TestReadMetadataPreservesAnExplicitBlockSize is the counter-test: filling in
// the absent case must not overwrite a real one.
func TestReadMetadataPreservesAnExplicitBlockSize(t *testing.T) {
	dir := t.TempDir()
	disk := filepath.Join(dir, "disk")
	if err := os.WriteFile(disk, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	rec := Volume{
		UUID: "11111111-1111-4111-8111-111111111111", WWN: "0000000000000000",
		Capacity: 1 << 20, State: Ready, BlockSize: MaxBlockSize,
	}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	v, err := ReadMetadataForDisk(disk)
	if err != nil {
		t.Fatal(err)
	}
	if v.BlockSize != MaxBlockSize {
		t.Errorf("a 4Kn volume's recorded geometry must survive the read, got %d", v.BlockSize)
	}
}
