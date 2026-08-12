package appliance

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/cwedgwood/glitr/lio"
)

// Handler returns the appliance REST API: a minimal bespoke shape over
// volumes, hosts and attachments, routed by method+path and served under
// APIPrefix.
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
		// Deliberately NOT part of the warning verdict below. This says the
		// appliance cannot answer the strand question for these volumes --
		// normal under multipath, where the kernel renders one session per ACL
		// and an initiator holds several. Reporting it as a warning is exactly
		// the false alarm it replaces; hiding it would let a detector go blind
		// in silence.
		if len(h.PRStrandUndecided) > 0 {
			body["pr_strand_undecided"] = h.PRStrandUndecided
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
		// Both flag warnings are served the same way, and for the same
		// reason: the appliance is not running the configuration its operator
		// believes it is, and the only place that is visible is here.
		if h.IQNFlagIgnored != "" {
			body["iqn_flag_ignored"] = h.IQNFlagIgnored
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

	// --- objects: volumes and snapshots ---
	//
	// Two collections over one record type, because a volume and a snapshot
	// are different things to a caller even though the bytes are identical.
	// The kind comes from the route, so a volume and a snapshot may hold the
	// same name without ambiguity.
	for _, k := range []Kind{KindVolume, KindSnapshot} {
		kind, coll := k, collectionOf(k)

		mux.HandleFunc("POST /"+coll, func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Name      string `json:"name"`
				Size      int64  `json:"size"`
				BlockSize int    `json:"block_size"`
				// Source names what to copy. For a snapshot it is the volume
				// being captured; for a volume it is the thing being cloned,
				// which may be a snapshot.
				Source     string `json:"source"`
				SourceKind string `json:"source_kind"`
			}
			if !readJSON(w, r, &req) {
				return
			}
			cr := CreateRequest{Name: req.Name, Size: req.Size, BlockSize: req.BlockSize,
				Source: req.Source, SourceKind: sourceKind(kind, req.SourceKind)}
			o, created, err := c.Create(kind, cr)
			respond(w, o, createdCode(created), err)
		})

		mux.HandleFunc("GET /"+coll, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, c.List(kind))
		})

		mux.HandleFunc("GET /"+coll+"/{name}", func(w http.ResponseWriter, r *http.Request) {
			o, ok := c.Get(kind, r.PathValue("name"))
			if !ok {
				errRespFor(w, notFound(string(kind), r.PathValue("name")))
				return
			}
			writeJSON(w, http.StatusOK, o)
		})

		// PATCH, because a rename changes one field and leaves the rest.
		mux.HandleFunc("PATCH /"+coll+"/{name}", func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Name string `json:"name"`
			}
			if !readJSON(w, r, &req) {
				return
			}
			o, err := c.Rename(kind, r.PathValue("name"), req.Name)
			respond(w, o, http.StatusOK, err)
		})

		mux.HandleFunc("DELETE /"+coll+"/{name}", func(w http.ResponseWriter, r *http.Request) {
			err := c.Delete(kind, r.PathValue("name"))
			respond(w, map[string]string{"deleted": r.PathValue("name")}, http.StatusOK, err)
		})

		mux.HandleFunc("POST /"+coll+"/{name}/resize", func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Size int64 `json:"size"`
			}
			if !readJSON(w, r, &req) {
				return
			}
			rescan, err := c.Resize(kind, r.PathValue("name"), req.Size)
			respond(w, map[string]bool{"rescan_required": rescan}, http.StatusOK, err)
		})

		// --- connections, nested so the kind is unambiguous ---
		mux.HandleFunc("POST /"+coll+"/{name}/connections", func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Host string `json:"host"`
				LUN  *int   `json:"lun"`
			}
			if !readJSON(w, r, &req) {
				return
			}
			lun, given := 0, req.LUN != nil
			if given {
				lun = *req.LUN
			}
			info, created, err := c.Connect(kind, r.PathValue("name"), req.Host, lun, given)
			respond(w, info, createdCode(created), err)
		})

		mux.HandleFunc("DELETE /"+coll+"/{name}/connections/{host}", func(w http.ResponseWriter, r *http.Request) {
			warning, err := c.Disconnect(kind, r.PathValue("name"), r.PathValue("host"))
			// The warning rides on BOTH paths: a reconcile failure inside
			// commit lands after the disconnect is durable, so the fence is
			// already lost and the caller still has to be told.
			respondWithWarning(w, map[string]any{"disconnected": r.PathValue("name")}, warning, err)
		})

		mux.HandleFunc("GET /"+coll+"/{name}/connections", func(w http.ResponseWriter, r *http.Request) {
			// The kind is the route, so this is never ambiguous even when a
			// volume and a snapshot share a name.
			v, err := c.ListConnections(r.PathValue("name"), kind, "")
			respond(w, v, http.StatusOK, err)
		})
	}

	// object_kind disambiguates ?object= when a volume and a snapshot share a
	// name. Optional, because most names are unique across the two and making
	// every caller state it would be noise; refused as ambiguous when it is
	// needed and absent, rather than answered with one of the two.
	mux.HandleFunc("GET /connections", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		v, err := c.ListConnections(q.Get("object"), Kind(q.Get("object_kind")), q.Get("host"))
		respond(w, v, http.StatusOK, err)
	})

	// --- hosts ---
	mux.HandleFunc("POST /hosts", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name string `json:"name"`
			// May be empty: a host is its name and uuid, not its bindings.
			IQNs []string `json:"iqns"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		h, created, err := c.CreateHost(req.Name, req.IQNs)
		respond(w, h, createdCode(created), err)
	})

	mux.HandleFunc("GET /hosts", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, c.ListHosts())
	})

	mux.HandleFunc("GET /hosts/{name}", func(w http.ResponseWriter, r *http.Request) {
		h, ok := c.GetHost(r.PathValue("name"))
		if !ok {
			errRespFor(w, notFound("host", r.PathValue("name")))
			return
		}
		writeJSON(w, http.StatusOK, h)
	})

	mux.HandleFunc("PATCH /hosts/{name}", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name string `json:"name"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		h, err := c.RenameHost(r.PathValue("name"), req.Name)
		respond(w, h, http.StatusOK, err)
	})

	// Bindings: replace the set, or add to and remove from it. Add/remove
	// exist because a node gaining a second initiator port should not have to
	// restate the ones it already had, and restating is how a caller
	// accidentally drops one -- which is a fencing event.
	mux.HandleFunc("PUT /hosts/{name}/iqns", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			IQNs []string `json:"iqns"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		if req.IQNs == nil {
			req.IQNs = []string{}
		}
		h, warning, err := c.SetBindings(r.PathValue("name"), req.IQNs, nil, nil)
		respondWithWarning(w, map[string]any{"host": h}, warning, err)
	})

	mux.HandleFunc("PATCH /hosts/{name}/iqns", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Add    []string `json:"add"`
			Remove []string `json:"remove"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		h, warning, err := c.SetBindings(r.PathValue("name"), nil, req.Add, req.Remove)
		respondWithWarning(w, map[string]any{"host": h}, warning, err)
	})

	mux.HandleFunc("DELETE /hosts/{name}", func(w http.ResponseWriter, r *http.Request) {
		respond(w, map[string]string{"deleted": r.PathValue("name")}, http.StatusOK,
			c.DeleteHost(r.PathValue("name")))
	})

	mux.HandleFunc("GET /hosts/{name}/connections", func(w http.ResponseWriter, r *http.Request) {
		v, err := c.ListConnections("", "", r.PathValue("name"))
		respond(w, v, http.StatusOK, err)
	})

	// Version at the mount point, not in every pattern: the route table above
	// stays readable, and a second version would be a second mount rather
	// than a rewrite of thirty strings.
	//
	// Adopted while the API had no external callers, which is the only cheap
	// moment. Unversioned paths are NOT served -- an alias would have to be
	// carried forever to be worth anything -- but they answer with a pointer
	// rather than a bare 404, because "GET /volumes returns 404" on an
	// otherwise healthy daemon is a genuinely confusing thing to debug.
	top := http.NewServeMux()
	top.Handle(APIPrefix+"/", http.StripPrefix(APIPrefix, mux))
	top.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		errResp(w, http.StatusNotFound, "the API is served under "+APIPrefix+"/")
	})
	return top
}

// APIPrefix is the mount point of the REST API. Every path documented for
// this appliance is relative to it.
const APIPrefix = "/v1"

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func errResp(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg, "code": codeForStatus(code)})
}

// errRespFor writes an error that carries its own machine-readable code.
func errRespFor(w http.ResponseWriter, err error) {
	var se *StatusError
	if errors.As(err, &se) {
		writeJSON(w, se.Code, map[string]string{"error": se.Msg, "code": se.ErrorCode()})
		return
	}
	writeJSON(w, http.StatusInternalServerError,
		map[string]string{"error": err.Error(), "code": CodeInternal})
}

// respond writes v with okCode, or maps the error to an HTTP status: a
// StatusError carries its own code; any other error is an unexpected
// internal failure (http.StatusInternalServerError).
// createdCode is 201 when a call made something and 200 when it returned what
// was already there.
//
// The distinction is the whole reason a repeat create is safe: a caller that
// cannot tell whether its first attempt landed replays it, and the status says
// which of the two happened. Answering 201 for both -- which this did -- makes
// the reply indistinguishable from a first success, so an external controller
// reconciling its own records cannot tell an adoption from a creation.
func createdCode(created bool) int {
	if created {
		return http.StatusCreated
	}
	return http.StatusOK
}

// respondWithWarning writes a result that may carry a warning, on either the
// success or the failure path.
//
// Both, because the warnings this carries report a fence that was lost, and a
// reconcile failure inside commit arrives AFTER the mutation is durable -- so
// the failure response is exactly the one an operator most needs the warning
// on, and the one they are least likely to read closely because something else
// already went wrong.
func respondWithWarning(w http.ResponseWriter, v map[string]any, warning string, err error) {
	if err != nil {
		code, msg, reason := http.StatusInternalServerError, err.Error(), CodeInternal
		var se *StatusError
		if errors.As(err, &se) {
			code, msg, reason = se.Code, se.Msg, se.ErrorCode()
		}
		body := map[string]any{"error": msg, "code": reason}
		if warning != "" {
			body["warning"] = warning
		}
		writeJSON(w, code, body)
		return
	}
	if warning != "" {
		v["warning"] = warning
	}
	writeJSON(w, http.StatusOK, v)
}

// collectionOf is the URL collection a kind is served under.
func collectionOf(k Kind) string {
	if k == KindSnapshot {
		return "snapshots"
	}
	return "volumes"
}

// sourceKind resolves what kind a create's source refers to.
//
// A snapshot is taken OF a volume and a volume is cloned FROM a snapshot, so
// the common case is the other kind -- but a volume can be cloned from a
// volume and a snapshot taken of a snapshot, so a caller can say.
func sourceKind(target Kind, given string) Kind {
	switch Kind(given) {
	case KindVolume, KindSnapshot:
		return Kind(given)
	}
	if target == KindSnapshot {
		return KindVolume
	}
	return KindSnapshot
}

func respond(w http.ResponseWriter, v any, okCode int, err error) {
	if err != nil {
		errRespFor(w, err)
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
