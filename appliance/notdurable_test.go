package appliance

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cwedgwood/glitr/storage"
)

// A volume create/snapshot that reports ErrPersistedNotDurable must still tell
// the caller the UUID it made.
//
// storage returns a real volume ALONGSIDE that error: persist renames the db
// into place and only then fsyncs the directory, so by the time it reports the
// failure the db already names the volume and its backing file is on disk.
// storage honours that contract (see storage's
// TestSnapshotDoesNotDestroyDataOnANonDurablePersist); the appliance did not.
// CreateVolume and SnapshotVolume both did
//
//	v, err := c.store.Create(...)
//	if err != nil { return storage.Volume{}, err }
//
// which threw the UUID away. The volume was real -- it showed up in
// GET /volumes and survived a reopen -- but the caller that created it never
// learned its name, so nothing could retry against it, resize it or delete it.
// One leaked volume per occurrence, permanently unattributable.
//
// The trigger is narrow (rename succeeded, directory fsync failed) and cannot
// be forced portably, so these assert the CODE PATH, the same way the storage
// test above does.

func TestVolumeResultKeepsTheVolumeWhenDurabilityIsUnproven(t *testing.T) {
	made := &storage.Volume{UUID: "u-1", Capacity: 1 << 20, State: storage.Ready}
	notDurable := fmt.Errorf("%w: fsync", storage.ErrPersistedNotDurable)

	v, err := volumeResult(made, notDurable)

	if !errors.Is(err, storage.ErrPersistedNotDurable) {
		t.Fatalf("the durability error must still be reported, got %v", err)
	}
	if v.UUID != made.UUID {
		t.Errorf("the caller must learn the UUID of the volume that was made: got %q, want %q", v.UUID, made.UUID)
	}
	if v.Capacity != made.Capacity {
		t.Errorf("capacity = %d, want %d", v.Capacity, made.Capacity)
	}
}

func TestVolumeResultReturnsZeroWhenNothingWasMade(t *testing.T) {
	// The ordinary failure: storage rolled back, there is no volume, and the
	// caller must not be handed a half-populated record.
	v, err := volumeResult(nil, errors.New("disk full"))
	if err == nil {
		t.Fatal("the error must be reported")
	}
	if v.UUID != "" {
		t.Errorf("no volume was created, so the result must be zero, got %+v", v)
	}
}

func TestVolumeResultPassesSuccessThrough(t *testing.T) {
	made := &storage.Volume{UUID: "u-2", Capacity: 4096}
	v, err := volumeResult(made, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.UUID != "u-2" || v.Capacity != 4096 {
		t.Errorf("got %+v, want the created volume", v)
	}
}

func TestRespondVolumeReportsTheUUIDWithTheDurabilityError(t *testing.T) {
	v := storage.Volume{UUID: "u-3", Capacity: 1 << 20}
	err := fmt.Errorf("%w: fsync", storage.ErrPersistedNotDurable)

	w := httptest.NewRecorder()
	respondVolume(w, v, http.StatusCreated, err)

	// 500, not 201: durability was NOT proven, so the caller must not treat
	// the volume as committed.
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d (durability unproven is still a failure)",
			w.Code, http.StatusInternalServerError)
	}
	var body struct {
		Error  string         `json:"error"`
		Volume storage.Volume `json:"volume"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, w.Body.String())
	}
	if body.Error == "" {
		t.Error("the error must be reported")
	}
	if body.Volume.UUID != "u-3" {
		t.Errorf("the body must name the volume that was made: got %q, want %q",
			body.Volume.UUID, "u-3")
	}
}

func TestRespondVolumeIsUnchangedForOrdinaryErrors(t *testing.T) {
	w := httptest.NewRecorder()
	respondVolume(w, storage.Volume{}, http.StatusCreated,
		statusErr(http.StatusBadRequest, "size too small"))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	if got := w.Body.String(); !json.Valid([]byte(got)) {
		t.Errorf("body is not JSON: %s", got)
	}
}

func TestRespondVolumeWritesTheVolumeOnSuccess(t *testing.T) {
	w := httptest.NewRecorder()
	respondVolume(w, storage.Volume{UUID: "u-4"}, http.StatusCreated, nil)

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", w.Code, http.StatusCreated)
	}
	var v storage.Volume
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("body is not a volume: %v (%s)", err, w.Body.String())
	}
	if v.UUID != "u-4" {
		t.Errorf("uuid = %q, want %q", v.UUID, "u-4")
	}
}
