package appliance

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/cwedgwood/glitr/lio"
	"github.com/cwedgwood/glitr/storage"
)

// Handler returns the appliance REST API: a minimal bespoke shape over
// volumes, hosts and attachments, routed by method+path.
//
// Handlers deliberately do NOT plumb r.Context() into the operations they
// call. Every mutation runs a reconcile, and configfs writes block
// uncancellably in the kernel -- so a context would advertise a cancellation
// that cannot happen, and a caller that acted on it would believe an
// operation stopped while the kernel was still applying it. The bound that
// does exist is the server's own write timeout, plus the fact that mutations
// are serialised, and those are honest about what they promise.
func Handler(c *Coordinator) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		// ONE snapshot. Reading the reconcile verdict and the PR warnings
		// separately let a reconcile land between them and pair an older
		// verdict with a newer warning.
		h := c.HealthSnapshot()

		// ONE body, built once, whatever the verdict. Every field below used
		// to be reachable only on the healthy path, so the fencing signals
		// disappeared exactly when an operator most needed them -- a failed
		// reconcile establishes nothing new about fencing, which is why
		// publishReconcileFailure deliberately KEEPS the previous warnings,
		// and the handler then threw them away. This repeats the fix already
		// made for rejected_records rather than leaving the same bug in the
		// fields that matter most.
		body := map[string]any{}
		// Saved PR state that is not in effect: a reservation someone relies
		// on for fencing is not protecting them.
		if len(h.PRUnbound) > 0 {
			body["pr_unbound"] = h.PRUnbound
		}
		// Reservations that ARE in effect but whose holder cannot release
		// them. Not "degraded", and deliberately a different key from
		// pr_unbound: that one means a fence someone relies on is NOT
		// protecting them, this one means it is protecting them and will not
		// stop. The appliance is healthy; what the operator needs is that
		// waiting for the holder to release is futile. Each entry carries its
		// own recovery, because preemption is not always available -- it needs
		// a registration the kernel can still locate.
		if len(h.PRStranded) > 0 {
			body["pr_stranded"] = h.PRStranded
		}
		// Managed attributes the kernel refused to change while the volume is
		// exported. Reported for the same reason as pr_unbound: the tree is
		// consistent, so this is not "degraded", but the live device does not
		// match what this appliance says about it and no reconcile can fix it.
		if len(h.Drift) > 0 {
			body["attribute_drift"] = h.Drift
		}
		// Not degraded -- the tree and the db agree and every operation is
		// still safe. But the recovery procedure for a lost db is "restore a
		// backup", so backups that have stopped being written must not be
		// discovered only at the moment they are needed.
		if h.BackupErr != "" {
			body["db_backup_failing"] = h.BackupErr
		}
		// Volume dirs with no db record, set aside rather than deleted. Not
		// degraded -- nothing exported is affected -- but one of these is
		// either dead space to reclaim or a live volume whose record was lost,
		// and only an operator can tell which. Silence would leave the second
		// case looking exactly like a volume that simply vanished.
		if len(h.Quarantined) > 0 {
			body["quarantined_volume_dirs"] = h.Quarantined
		}
		// Db records excluded from the live set. Unlike the quarantined dirs
		// above this IS degraded: a volume an operator believes exists is not
		// being exported, and the record naming it is sitting in the db.
		if len(h.RejectedRecords) > 0 {
			body["rejected_records"] = h.RejectedRecords
		}
		// When the PR state was last checked. Without this "no pr_unbound"
		// is ambiguous between "checked, nothing wrong" and "never
		// successfully checked", which matters because the check is
		// periodic rather than computed per request.
		//
		// RFC3339Nano, not RFC3339. A reconcile and the /health read that
		// follows it routinely fall in the same second, so at second
		// resolution two genuinely distinct checks stamped identically and a
		// caller could not tell a fresh computation from a stale one re-served
		// -- which is exactly the question this field exists to answer. Still
		// valid RFC 3339, so any parser that handled the old form handles this.
		// MEASURED: the aptpl-scope suite's freshness assertion failed against
		// a correctly-recomputed signal for this reason alone.
		if h.PortalFlagIgnored != "" {
			body["portal_flag_ignored"] = h.PortalFlagIgnored
		}
		if !h.CheckedAt.IsZero() {
			body["pr_checked_at"] = h.CheckedAt.UTC().Format(time.RFC3339Nano)
		}

		// The top-level verdict has to reflect the fencing signals, because
		// that is what anything automated actually reads. This returned
		// status "ok" with pr_unbound sitting in the same object: an ordinary
		// monitor checks the status code or the status field, not every
		// optional key, so the appliance reported itself healthy in precisely
		// the condition this project describes as its worst failure.
		//
		// Still HTTP 200 when only fencing is affected. The appliance IS
		// alive and serving, and answering 503 would have a liveness probe
		// restart a working daemon -- which does not restore the reservation
		// and does interrupt the volumes that are fine. The status code
		// answers "is it running", the status field answers "is it right".
		switch {
		case h.Degraded:
			body["status"] = "degraded"
			body["error"] = h.Detail
			writeJSON(w, http.StatusServiceUnavailable, body)
		case len(h.PRUnbound) > 0 || len(h.PRStranded) > 0:
			body["status"] = "warning"
			writeJSON(w, http.StatusOK, body)
		default:
			body["status"] = "ok"
			writeJSON(w, http.StatusOK, body)
		}
	})

	mux.HandleFunc("GET /target", func(w http.ResponseWriter, r *http.Request) {
		// Portals are returned as endpoints, each with its own port. There is
		// no top-level "port": one used to sit beside a list of bare
		// addresses, which told a client that every portal shared it. iSCSI
		// says otherwise -- a portal is an address AND a port (RFC 3720
		// TargetAddress is <address>[:<port>],<tag>), which is why SendTargets
		// answers "10.0.0.1:3260,1" per portal.
		iqn, portals := c.Target()
		writeJSON(w, http.StatusOK, map[string]any{"target_iqn": iqn, "portals": portals})
	})

	// PUT rather than POST: the body is the COMPLETE desired portal list, and
	// the operation is idempotent -- sending the same list twice is a no-op,
	// not a second change. There is deliberately no per-portal add/remove
	// endpoint: portals have ordering constraints between them (a wildcard
	// cannot bind while another address holds its port), so the whole set is
	// the only unit that can be validated and applied coherently.
	mux.HandleFunc("PUT /target/portals", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			// Portals accepts the same syntax as the -portals flag: a list of
			// "ip" or "ip:port" strings, IPv6 bracketed when a port is given.
			Portals []string `json:"portals"`
			// Port defaults entries that carry no port of their own.
			Port uint16 `json:"port"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		if req.Port == 0 {
			req.Port = lio.DefaultPortalPort
		}
		// Hand an empty list straight to SetPortals so ITS guard answers.
		// Joining an empty slice yields "", which ParsePortals reports as a
		// malformed address -- a true statement about the wrong thing, and it
		// buries the actual reason the request is refused.
		if len(req.Portals) == 0 {
			_, err := c.SetPortals(nil)
			respond(w, nil, http.StatusOK, err)
			return
		}
		parsed, perr := ParsePortals(strings.Join(req.Portals, ","), req.Port)
		if perr != nil {
			errResp(w, http.StatusBadRequest, perr.Error())
			return
		}
		out, err := c.SetPortals(parsed)
		respond(w, map[string]any{"portals": out}, http.StatusOK, err)
	})

	// --- volumes ---
	mux.HandleFunc("POST /volumes", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Size int64 `json:"size"`
			// BlockSize is the logical block size the initiator will see:
			// 512 (default) or 4096. Fixed for the life of the volume.
			BlockSize int `json:"block_size"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		v, err := c.CreateVolume(req.Size, req.BlockSize)
		respondVolume(w, v, http.StatusCreated, err)
	})

	mux.HandleFunc("GET /volumes", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, c.ListVolumes())
	})

	mux.HandleFunc("GET /volumes/{uuid}", func(w http.ResponseWriter, r *http.Request) {
		v, ok := c.GetVolume(r.PathValue("uuid"))
		if !ok {
			errResp(w, http.StatusNotFound, "volume not found")
			return
		}
		writeJSON(w, http.StatusOK, v)
	})

	mux.HandleFunc("DELETE /volumes/{uuid}", func(w http.ResponseWriter, r *http.Request) {
		respond(w, map[string]string{"deleted": r.PathValue("uuid")}, http.StatusOK, c.DeleteVolume(r.PathValue("uuid")))
	})

	mux.HandleFunc("POST /volumes/{uuid}/resize", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Size int64 `json:"size"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		rescan, err := c.ResizeVolume(r.PathValue("uuid"), req.Size)
		respond(w, map[string]bool{"rescan_required": rescan}, http.StatusOK, err)
	})

	mux.HandleFunc("POST /volumes/{uuid}/snapshot", func(w http.ResponseWriter, r *http.Request) {
		v, err := c.SnapshotVolume(r.PathValue("uuid"))
		respondVolume(w, v, http.StatusCreated, err)
	})

	mux.HandleFunc("POST /volumes/{uuid}/lunmap", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Host string `json:"host"`
			LUN  int    `json:"lun"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		info, err := c.Lunmap(r.PathValue("uuid"), req.Host, req.LUN)
		respond(w, info, http.StatusOK, err)
	})

	mux.HandleFunc("POST /volumes/{uuid}/lununmap", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Host string `json:"host"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		// The warning goes in the RESPONSE, not only the log. The operator
		// issuing the detach is the one who needs to know it released a
		// reservation, at the moment they do it -- a log line is read later,
		// if at all.
		warning, err := c.Lununmap(r.PathValue("uuid"), req.Host)
		// The warning is carried on BOTH paths. A reconcile failure inside
		// commit arrives after the detach is durable, so the fence is still
		// lost and the operator still needs to be told -- and that is exactly
		// the response they are least likely to read carefully, because it
		// already reports a failure.
		if err != nil {
			code, msg := http.StatusInternalServerError, err.Error()
			var se *StatusError
			if errors.As(err, &se) {
				code, msg = se.Code, se.Msg
			}
			body := map[string]string{"error": msg}
			if warning != "" {
				body["warning"] = warning
			}
			writeJSON(w, code, body)
			return
		}
		body := map[string]string{"detached": r.PathValue("uuid")}
		if warning != "" {
			body["warning"] = warning
		}
		writeJSON(w, http.StatusOK, body)
	})

	// --- hosts ---
	mux.HandleFunc("POST /hosts", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			IQNs []string `json:"iqns"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		h, err := c.CreateHost(req.IQNs)
		respond(w, h, http.StatusCreated, err)
	})

	mux.HandleFunc("GET /hosts", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, c.ListHosts())
	})

	mux.HandleFunc("DELETE /hosts/{uuid}", func(w http.ResponseWriter, r *http.Request) {
		respond(w, map[string]string{"deleted": r.PathValue("uuid")}, http.StatusOK, c.DeleteHost(r.PathValue("uuid")))
	})

	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func errResp(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// respondVolume writes the result of an operation that mints a new volume
// identity (create, snapshot).
//
// It differs from respond in one case: storage can return a REAL volume
// alongside ErrPersistedNotDurable, where the db already names the volume but
// the directory fsync was not proven. The status stays 500 -- the caller may
// not assume the record survives a power cut -- but the body must carry the
// volume, or the caller is left with a volume it cannot name, retry against,
// or delete. respond drops the value whenever err is non-nil, which is right
// everywhere else and wrong here.
func respondVolume(w http.ResponseWriter, v storage.Volume, okCode int, err error) {
	if errors.Is(err, storage.ErrPersistedNotDurable) && v.UUID != "" {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error":  err.Error(),
			"volume": v,
		})
		return
	}
	respond(w, v, okCode, err)
}

// respond writes v with okCode, or maps the error to an HTTP status: a
// StatusError carries its own code; any other error is an unexpected
// internal failure (http.StatusInternalServerError).
func respond(w http.ResponseWriter, v any, okCode int, err error) {
	if err != nil {
		var se *StatusError
		if errors.As(err, &se) {
			errResp(w, se.Code, se.Msg)
		} else {
			errResp(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	writeJSON(w, okCode, v)
}

// readJSON decodes the request body (capped at 1 MiB); on error it writes
// http.StatusBadRequest and returns false.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		errResp(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}
