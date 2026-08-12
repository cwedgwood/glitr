// Package applianceclient is a Go client for the glitr appliance's REST API.
//
// It is deliberately thin: it encodes requests, decodes responses, and turns
// an error body into a typed error. It does not retry, authenticate, negotiate
// TLS, tunnel, or decide anything. Those are policies, they differ per
// deployment, and a client that guessed at them would have to be worked around
// rather than used -- supply an *http.Client that implements the ones you want.
//
// The types here are COPIES of the appliance's, not aliases. That is the point
// of the package: the wire format is the contract, so a caller can compile
// against this without importing the server, and the appliance can rearrange
// its internals without breaking anyone. Fields are added, not repurposed.
package applianceclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// APIPrefix is the version this client speaks. Every path is relative to it.
const APIPrefix = "/v1"

// maxErrorBody bounds what is read from an error response.
//
// An error body is small by construction, so anything large is a proxy's
// output or a wrong endpoint. Reading it all would let a misdirected client
// buffer an unbounded amount of someone else's HTML.
const maxErrorBody = 64 << 10

// Kind separates the namespaces an object lives in. A volume and a snapshot
// may hold the same name; they are different things.
type Kind string

const (
	KindVolume   Kind = "volume"
	KindSnapshot Kind = "snapshot"
)

// Object is a volume or a snapshot as the appliance reports it.
//
// Name is what you address it by. UUID is its identity and works anywhere a
// name does. WWN is what an initiator identifies the device by, and does not
// change when the object is renamed.
type Object struct {
	UUID      string `json:"uuid"`
	Name      string `json:"name"`
	Kind      Kind   `json:"kind"`
	WWN       string `json:"wwn"`
	Capacity  int64  `json:"capacity"`
	BlockSize int    `json:"block_size"`
	Created   string `json:"created"`
	State     string `json:"state"`
	// Source is what this was made from, if anything: the volume a snapshot
	// was taken of, or the object a clone was copied from.
	Source string `json:"source,omitempty"`
}

// Bindings are the fabric identities that let an initiator log in as a host.
// Only iSCSI is implemented; the shape leaves room for others.
type Bindings struct {
	IQNs []string `json:"iqns,omitempty"`
}

// Host is an initiator. Bindings may be empty: a host is its name and uuid,
// not the identities bound to it.
type Host struct {
	UUID     string   `json:"uuid"`
	Name     string   `json:"name"`
	Bindings Bindings `json:"bindings"`
}

// Portal is one address the target listens on.
type Portal struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// ConnInfo is what an initiator needs to reach a mapped volume.
type ConnInfo struct {
	TargetIQN string   `json:"target_iqn"`
	Portals   []Portal `json:"portals"`
	LUN       int      `json:"lun"`
	Wwid      string   `json:"wwid"`
}

// Connection is one object exported to one host at one LUN.
type Connection struct {
	Object     string `json:"object"`
	ObjectKind Kind   `json:"object_kind"`
	ObjectUUID string `json:"object_uuid"`
	Host       string `json:"host"`
	HostUUID   string `json:"host_uuid"`
	LUN        int    `json:"lun"`
	TargetIQN  string `json:"target_iqn"`
	Wwid       string `json:"wwid"`
}

// Health is the appliance's verdict on itself. Status is "ok", "warning" or
// "degraded"; read the body rather than only the HTTP status, because a
// warning is served with 200 and still means fencing state needs attention.
type Health struct {
	Status                string   `json:"status"`
	Error                 string   `json:"error,omitempty"`
	QuarantinedVolumeDirs []string `json:"quarantined_volume_dirs,omitempty"`
	PRUnbound             []string `json:"pr_unbound,omitempty"`
	PRStranded            []string `json:"pr_stranded,omitempty"`
	// PRStrandUndecided names targets where the appliance cannot tell whether
	// a reservation is stranded, because the kernel renders one session per
	// ACL and the initiator holds several (multipath). It is NOT a fault and
	// does not make Status a warning: nothing is wrong with the reservation.
	PRStrandUndecided []string `json:"pr_strand_undecided,omitempty"`
	AttributeDrift    []string `json:"attribute_drift,omitempty"`
	// PortalFlagIgnored and IQNFlagIgnored are set when the appliance was
	// started with a -portals or -iqn that disagrees with what it has
	// recorded. Neither is an error -- the record wins by design -- but an
	// operator who edited a unit file and restarted is otherwise left to
	// discover that nothing happened.
	PortalFlagIgnored string `json:"portal_flag_ignored,omitempty"`
	IQNFlagIgnored    string `json:"iqn_flag_ignored,omitempty"`
}

// Error is a failure the appliance reported, as opposed to a transport
// failure. Code is the stable machine-readable code; branch on it rather than
// on Message, which is prose and may be reworded.
type Error struct {
	StatusCode int
	Code       string
	Message    string
	// Warning is a fencing statement the appliance attached to a FAILED
	// mutation, and it is not decoration.
	//
	// A mutation that reports a lost reservation can fail after it is already
	// durable -- the reconcile that follows the commit is what failed -- so
	// the fence is gone AND the call returned an error. Retrying then takes
	// the idempotent path, which succeeds and says nothing, so a caller that
	// discarded this never learns fencing was lost. It is rendered by Error()
	// for that reason: a caller that only logs err still sees the sentence.
	Warning string
}

func (e *Error) Error() string {
	var s string
	if e.Code != "" {
		s = fmt.Sprintf("appliance: %s (%s, HTTP %d)", e.Message, e.Code, e.StatusCode)
	} else {
		s = fmt.Sprintf("appliance: %s (HTTP %d)", e.Message, e.StatusCode)
	}
	if e.Warning != "" {
		s += " [WARNING: " + e.Warning + "]"
	}
	return s
}

// IsCode reports whether err is an appliance error with the given code.
func IsCode(err error, code string) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}

// Error codes the appliance sends. Mirrored here so a caller can branch
// without importing the server; unknown codes are possible and must not be
// treated as fatal.
const (
	CodeNotFound              = "not_found"
	CodeAlreadyExists         = "already_exists"
	CodeConfigurationMismatch = "configuration_mismatch"
	CodeResourceConnected     = "resource_connected"
	CodeLUNConflict           = "lun_conflict"
	CodeInvalidInput          = "invalid_input"
	CodeUnsupportedState      = "unsupported_state"
	CodeReconcileFailed       = "reconcile_failed"
	CodeInternal              = "internal"
	CodeNameTaken             = "name_taken"
	CodeLUNRequired           = "lun_required"
)

// Client talks to one appliance.
type Client struct {
	endpoint *url.URL
	http     *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient supplies the http.Client to use. This is where timeouts,
// TLS and any transport-level policy belong.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) {
		if h != nil {
			c.http = h
		}
	}
}

// New returns a client for the appliance at endpoint, e.g.
// "http://127.0.0.1:8080". The version prefix is added by the client; do not
// include it.
func New(endpoint string, opts ...Option) (*Client, error) {
	if endpoint == "" {
		return nil, errors.New("applianceclient: empty endpoint")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("applianceclient: bad endpoint %q: %w", endpoint, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("applianceclient: endpoint %q needs an http or https scheme", endpoint)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("applianceclient: endpoint %q has no host", endpoint)
	}
	// Trailing slashes are dropped so the caller's spelling does not change
	// the paths that get built.
	u.Path = strings.TrimRight(u.Path, "/")
	c := &Client{endpoint: u, http: http.DefaultClient}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// url builds a request URL from path SEGMENTS.
//
// Segments rather than a formatted string because a UUID or a caller-supplied
// name is interpolated into the path, and a value containing a separator must
// not be able to introduce new path segments. Both the decoded and the encoded
// form are set: url.URL.String() escapes Path itself, so pre-escaping a
// segment and assigning it to Path produced %252F -- escaped twice, matching
// nothing.
func (c *Client) url(query url.Values, segments ...string) string {
	dec := make([]string, len(segments))
	esc := make([]string, len(segments))
	for i, seg := range segments {
		dec[i] = seg
		esc[i] = url.PathEscape(seg)
	}
	u := *c.endpoint
	base := u.Path + APIPrefix
	u.Path = base + "/" + strings.Join(dec, "/")
	u.RawPath = base + "/" + strings.Join(esc, "/")
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}
	return u.String()
}

// do performs a request and decodes the response into out (which may be nil).
func (c *Client) do(ctx context.Context, method string, segments []string, query url.Values, body, out any) error {
	_, err := c.doStatus(ctx, method, segments, query, body, out)
	return err
}

// send performs a request and returns the live response. The caller closes the
// body.
//
// Split out because [Client.Health] has to read a body that doStatus would
// discard: the appliance reports "degraded" as 503 carrying the ordinary
// health object, and that object is the answer rather than an error.
func (c *Client) send(ctx context.Context, method string, segments []string, query url.Values, body any) (*http.Response, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("applianceclient: encoding request: %w", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.url(query, segments...), rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	return c.http.Do(req)
}

// doStatus is do, reporting the response status.
//
// Separate because only the calls that can either make something or find it
// already there need the code, and every other call reading a status it does
// not use would be an invitation to branch on one by accident.
func (c *Client) doStatus(ctx context.Context, method string, segments []string, query url.Values, body, out any) (int, error) {
	resp, err := c.send(ctx, method, segments, query, body)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		// The result is decoded on the FAILURE path too. A failed mutation
		// still carries what the appliance managed to say about it, and for
		// the warning-bearing calls that is a fence that was lost. Leaving
		// the result zero because the call failed threw it away twice: once
		// here and once in the error.
		//
		// Best effort by design: an error body from a proxy is not this
		// struct, and failing to decode it must not replace a usable HTTP
		// status with "decode failed".
		if out != nil {
			_ = json.Unmarshal(raw, out)
		}
		return resp.StatusCode, errorFromBody(resp.StatusCode, resp.Status, raw)
	}
	if out == nil {
		// Drained rather than ignored, so the connection can be reused.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBody))
		return resp.StatusCode, nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return resp.StatusCode, fmt.Errorf("applianceclient: decoding %s %s: %w", method, strings.Join(segments, "/"), err)
	}
	return resp.StatusCode, nil
}

// errorFromBody builds an *Error from a response body already read.
//
// A body that is not the appliance's JSON still yields an *Error carrying the
// status: a proxy returning HTML must not become "decode failed", which would
// hide the status the caller needs.
func errorFromBody(status int, statusText string, raw []byte) error {
	e := &Error{StatusCode: status}
	var body struct {
		Error   string `json:"error"`
		Code    string `json:"code"`
		Warning string `json:"warning"`
	}
	if err := json.Unmarshal(raw, &body); err == nil && body.Error != "" {
		e.Message, e.Code, e.Warning = body.Error, body.Code, body.Warning
		return e
	}
	e.Message = strings.TrimSpace(string(raw))
	if e.Message == "" {
		e.Message = statusText
	}
	return e
}

// --- health ---

// Health returns the appliance's self-assessment.
//
// Read Status, not the error. A degraded appliance answers HTTP 503 and a
// warning answers 200, but BOTH carry the same body, and the body is the
// verdict: the status code says whether the daemon is serving, Status says
// whether it is right. This returns the decoded body with a nil error for
// either, because the one moment a caller most needs pr_unbound and the detail
// is the moment the appliance says it is degraded -- and turning that into a
// bare error, as this used to, discarded exactly then.
//
// An error means the answer is not the appliance's: unreachable, a proxy, or a
// body that carries no verdict. A zero Health has an empty Status, which no
// caller should read as healthy.
func (c *Client) Health(ctx context.Context) (Health, error) {
	resp, err := c.send(ctx, http.MethodGet, []string{"health"}, nil, nil)
	if err != nil {
		return Health{}, err
	}
	defer resp.Body.Close()

	// Bounded like any other body: a proxy answering 503 with a page of HTML
	// must not be read into memory in full.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	if err != nil {
		return Health{}, fmt.Errorf("applianceclient: reading health: %w", err)
	}

	var h Health
	if json.Unmarshal(raw, &h) == nil && h.Status != "" {
		// A verdict, whatever the status code carrying it. Decoded from the
		// body rather than rebuilt from an error, so pr_unbound and
		// pr_stranded survive -- they are the reason to call this at all, and
		// they exist ONLY in the body.
		return h, nil
	}
	return Health{}, errorFromBody(resp.StatusCode, resp.Status, raw)
}

// --- target ---

// Target is the iSCSI target an initiator logs in to: the IQN to address and
// the portals to reach it on.
//
// Kept apart from a connection because it belongs to the appliance rather than
// to any one export -- every connection shares it. [Connection] therefore
// carries the target IQN but no portals: repeating the portal list on every
// row would be the same answer many times, and stale in every copy the moment
// the set changes.
type Target struct {
	TargetIQN string   `json:"target_iqn"`
	Portals   []Portal `json:"portals"`
}

// Target returns the target IQN and the portals it listens on.
//
// This is what an initiator needs alongside a connection's LUN and WWID, and
// it is the reason [Client.ListConnections] does not have to report portals:
// ask once, use for every connection.
func (c *Client) Target(ctx context.Context) (Target, error) {
	var t Target
	err := c.do(ctx, http.MethodGet, []string{"target"}, nil, nil, &t)
	return t, err
}

// --- objects: volumes and snapshots ---

// CreateRequest asks for a volume or a snapshot.
//
// Name is required and is what you address the result by. Repeating a create
// with a name that exists returns the existing object rather than making a
// second, which is what makes a create safe to retry.
type CreateRequest struct {
	Name string `json:"name"`
	// Size in bytes. The appliance enforces a minimum and a granularity and
	// names both in the error if they are not met; the numbers are the
	// server's to state, and are deliberately not repeated here, where
	// nothing could keep them true. Ignored when Source is set and Size is
	// zero, in which case the source's size is inherited; a larger Size grows
	// the copy.
	Size int64 `json:"size,omitempty"`
	// BlockSize is what an initiator is told a sector is, and is fixed for the
	// life of the object. Zero asks for the appliance's default; the set it
	// accepts is the server's to state. Ignored when Source is set: a copy
	// shares the source's geometry, because the filesystem inside it was
	// written for that geometry and would be misread at another.
	BlockSize int `json:"block_size,omitempty"`
	// Source is what to copy, by name or uuid. For a snapshot it is the
	// volume being captured; for a volume it is the thing being cloned.
	Source string `json:"source,omitempty"`
	// SourceKind says which namespace Source is in. Empty means the other one,
	// which is the common case: snapshots are taken of volumes and volumes are
	// cloned from snapshots.
	SourceKind Kind `json:"source_kind,omitempty"`
}

func collection(k Kind) string {
	if k == KindSnapshot {
		return "snapshots"
	}
	return "volumes"
}

// CreateVolume creates a volume, or returns the existing one of that name.
//
// created reports which of those happened: true when this call made it (HTTP
// 201), false when the name was already taken by a matching volume and it was
// returned unchanged (HTTP 200). Both are successes -- that is what makes a
// create safe to replay -- but a controller reconciling against its own
// records has to tell an adoption from a creation.
//
// The returned object describes what is actually there, which need not be what
// was asked for: capacity is deliberately not compared on a repeat create,
// because an object can be resized after it is made. Compare Capacity yourself
// if a size difference means something to you.
func (c *Client) CreateVolume(ctx context.Context, req CreateRequest) (o Object, created bool, err error) {
	return c.create(ctx, KindVolume, req)
}

// CreateSnapshot captures a volume as a named snapshot. created has the same
// meaning as on [Client.CreateVolume].
func (c *Client) CreateSnapshot(ctx context.Context, req CreateRequest) (o Object, created bool, err error) {
	return c.create(ctx, KindSnapshot, req)
}

func (c *Client) create(ctx context.Context, kind Kind, req CreateRequest) (Object, bool, error) {
	var o Object
	code, err := c.doStatus(ctx, http.MethodPost, []string{collection(kind)}, nil, req, &o)
	return o, code == http.StatusCreated, err
}

// List returns every object of a kind.
func (c *Client) List(ctx context.Context, kind Kind) ([]Object, error) {
	var out []Object
	err := c.do(ctx, http.MethodGet, []string{collection(kind)}, nil, nil, &out)
	return out, err
}

// Get returns one object by name, or by uuid.
func (c *Client) Get(ctx context.Context, kind Kind, ref string) (Object, error) {
	var o Object
	err := c.do(ctx, http.MethodGet, []string{collection(kind), ref}, nil, nil, &o)
	return o, err
}

// Rename changes an object's name.
//
// Safe while it is exported and mounted: an initiator identifies the device by
// its WWN, which does not move.
func (c *Client) Rename(ctx context.Context, kind Kind, ref, newName string) (Object, error) {
	var o Object
	err := c.do(ctx, http.MethodPatch, []string{collection(kind), ref}, nil,
		map[string]string{"name": newName}, &o)
	return o, err
}

// Delete removes an object. Refused while it is connected.
func (c *Client) Delete(ctx context.Context, kind Kind, ref string) error {
	return c.do(ctx, http.MethodDelete, []string{collection(kind), ref}, nil, nil, nil)
}

// ResizeResponse reports whether initiators must rescan to see the new size.
type ResizeResponse struct {
	RescanRequired bool `json:"rescan_required"`
}

// Resize grows an object. Shrinking is not supported.
func (c *Client) Resize(ctx context.Context, kind Kind, ref string, size int64) (ResizeResponse, error) {
	var r ResizeResponse
	err := c.do(ctx, http.MethodPost, []string{collection(kind), ref, "resize"}, nil,
		map[string]int64{"size": size}, &r)
	return r, err
}

// --- hosts ---

// CreateHost registers a host, or returns the existing one of that name when
// its bindings match. IQNs may be empty for a host whose initiator identity is
// not known yet. created has the same meaning as on [Client.CreateVolume].
func (c *Client) CreateHost(ctx context.Context, name string, iqns []string) (h Host, created bool, err error) {
	if iqns == nil {
		iqns = []string{}
	}
	var host Host
	code, err := c.doStatus(ctx, http.MethodPost, []string{"hosts"}, nil,
		map[string]any{"name": name, "iqns": iqns}, &host)
	return host, code == http.StatusCreated, err
}

// ListHosts returns every host.
func (c *Client) ListHosts(ctx context.Context) ([]Host, error) {
	var hs []Host
	err := c.do(ctx, http.MethodGet, []string{"hosts"}, nil, nil, &hs)
	return hs, err
}

// GetHost returns one host by name, or by uuid.
func (c *Client) GetHost(ctx context.Context, ref string) (Host, error) {
	var h Host
	err := c.do(ctx, http.MethodGet, []string{"hosts", ref}, nil, nil, &h)
	return h, err
}

// RenameHost changes a host's name, keeping its uuid, bindings and connections.
func (c *Client) RenameHost(ctx context.Context, ref, newName string) (Host, error) {
	var h Host
	err := c.do(ctx, http.MethodPatch, []string{"hosts", ref}, nil,
		map[string]string{"name": newName}, &h)
	return h, err
}

// HostResponse carries a host and, when the change cost somebody their access,
// a warning.
//
// Populated on FAILURE too: the mutation can be durable before the error
// happens, so a non-nil error does not mean nothing changed. The same warning
// is on the returned error -- see [Error.Warning].
//
// Warning is NOT decoration. Removing a binding removes its ACL, and the
// kernel releases a reservation whose holder loses its mapped LUN -- so a
// caller that discards this can silently drop a fence. Log it, at minimum.
type HostResponse struct {
	Host    Host   `json:"host"`
	Warning string `json:"warning,omitempty"`
}

// SetBindings replaces a host's entire binding set.
//
// Prefer AddBindings and RemoveBindings where you can: restating a whole set
// is how a caller accidentally drops one it meant to keep.
func (c *Client) SetBindings(ctx context.Context, ref string, iqns []string) (HostResponse, error) {
	if iqns == nil {
		iqns = []string{}
	}
	var r HostResponse
	err := c.do(ctx, http.MethodPut, []string{"hosts", ref, "iqns"}, nil,
		map[string][]string{"iqns": iqns}, &r)
	return r, err
}

// AddBindings adds bindings without restating the ones already there.
func (c *Client) AddBindings(ctx context.Context, ref string, iqns []string) (HostResponse, error) {
	var r HostResponse
	err := c.do(ctx, http.MethodPatch, []string{"hosts", ref, "iqns"}, nil,
		map[string][]string{"add": iqns}, &r)
	return r, err
}

// RemoveBindings removes bindings. This can release a reservation; see
// HostResponse.Warning.
func (c *Client) RemoveBindings(ctx context.Context, ref string, iqns []string) (HostResponse, error) {
	var r HostResponse
	err := c.do(ctx, http.MethodPatch, []string{"hosts", ref, "iqns"}, nil,
		map[string][]string{"remove": iqns}, &r)
	return r, err
}

// DeleteHost removes a host. Refused while it has connections.
func (c *Client) DeleteHost(ctx context.Context, ref string) error {
	return c.do(ctx, http.MethodDelete, []string{"hosts", ref}, nil, nil, nil)
}

// --- connections ---

// Connect exports an object to a host at a LUN, and returns what an initiator
// needs to reach it.
//
// The LUN is required: the appliance never assigns one, because in a cluster
// the same object usually has to appear at the same LUN on every node. Safe to
// retry -- connecting something already connected at that LUN returns the same
// details rather than a conflict, and created says which happened (see
// [Client.CreateVolume]).
func (c *Client) Connect(ctx context.Context, kind Kind, objectRef, hostRef string, lun int) (info ConnInfo, created bool, err error) {
	var ci ConnInfo
	code, err := c.doStatus(ctx, http.MethodPost,
		[]string{collection(kind), objectRef, "connections"}, nil,
		map[string]any{"host": hostRef, "lun": lun}, &ci)
	return ci, code == http.StatusCreated, err
}

// DisconnectResponse reports the disconnect and, when it released a
// reservation, says so. Warning has the same weight as on HostResponse, and is
// likewise populated on failure.
type DisconnectResponse struct {
	Disconnected string `json:"disconnected,omitempty"`
	Warning      string `json:"warning,omitempty"`
}

// Disconnect withdraws an object from a host. Disconnecting something already
// disconnected succeeds.
func (c *Client) Disconnect(ctx context.Context, kind Kind, objectRef, hostRef string) (DisconnectResponse, error) {
	var r DisconnectResponse
	err := c.do(ctx, http.MethodDelete,
		[]string{collection(kind), objectRef, "connections", hostRef}, nil, nil, &r)
	return r, err
}

// ListConnections returns current connections. Empty objectRef or hostRef
// means no filter on that field.
//
// objectKind says which namespace objectRef is in. Empty means either, which
// the appliance accepts while the name is unique across the two and REFUSES
// once it is not -- a volume and a snapshot may both be called "db-1", and
// answering with one of them would report the other as having no connections.
// Pass the kind whenever you know it; a uuid is never ambiguous.
func (c *Client) ListConnections(ctx context.Context, objectRef string, objectKind Kind, hostRef string) ([]Connection, error) {
	q := url.Values{}
	if objectRef != "" {
		q.Set("object", objectRef)
	}
	if objectKind != "" {
		q.Set("object_kind", string(objectKind))
	}
	if hostRef != "" {
		q.Set("host", hostRef)
	}
	var out []Connection
	err := c.do(ctx, http.MethodGet, []string{"connections"}, q, nil, &out)
	return out, err
}
