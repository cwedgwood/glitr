// Command applianced runs the glitr storage appliance and its host-prep
// tooling. Subcommands:
//
//	applianced [serve]      run the daemon: startup replay + REST API (default)
//	applianced preflight    read-only host readiness check
//	applianced setup-system idempotent host preparation (root)
//	applianced inspect      read-only dump of the live LIO tree
//
// Example bring-up on a fresh host:
//
//	applianced preflight -root /var/lib/glitr
//	applianced setup-system -data-disk /dev/vdb
//	systemctl enable --now applianced
//
// Give -data-disk at SETUP, before any volume exists. It is optional and the
// appliance runs without it, but the data root then lands on the root
// filesystem, which typically cannot clone extents -- so every snapshot fails.
// setup-system says which of the two you have got. Adding the disk later means
// mounting over a data root that already holds volumes, which HIDES them
// rather than moving them; setup-system refuses that unless given
// -force-mount.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cwedgwood/glitr/appliance"
	"github.com/cwedgwood/glitr/hostlock"
	"github.com/cwedgwood/glitr/lio"
	"github.com/cwedgwood/glitr/lio/configfs"
	"github.com/cwedgwood/glitr/setup"
	"github.com/cwedgwood/glitr/storage"
)

func main() {
	args := os.Args[1:]
	sub := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "serve":
		serve(args)
	case "preflight":
		preflightCmd(args)
	case "setup-system":
		setupCmd(args)
	case "inspect":
		inspectCmd(args)
	case "help", "-h", "--help":
		usage(os.Stdout)
	default:
		usage(os.Stderr)
		log.Fatalf("unknown subcommand %q", sub)
	}
}

// usage lists the subcommands. `applianced help` is the first thing most
// people type, so it answers rather than failing, and an unknown subcommand
// gets the same list instead of only being told it was wrong.
func usage(w io.Writer) {
	fmt.Fprint(w, `applianced — iSCSI storage appliance

  applianced serve [flags]          run the daemon (the default with no subcommand)
  applianced preflight [flags]      check host readiness, changing nothing
  applianced setup-system [flags]   prepare the host to run the daemon (root)
  applianced inspect [flags]        report what is configured and live

Run any subcommand with -h for its flags.
`)
}

// setupCmd idempotently prepares the host to run applianced (root).
func setupCmd(args []string) {
	fs := flag.NewFlagSet("setup-system", flag.ExitOnError)
	root := fs.String("root", "/var/lib/glitr", "storage root (XFS mount point)")
	dataDisk := fs.String("data-disk", "", "block device to format XFS + mount at -root (optional)")
	force := fs.Bool("force", false, "allow mkfs over a device that already has a filesystem")
	forceMount := fs.Bool("force-mount", false, "allow mounting the data disk over a non-empty data root (hides existing data)")
	enable := fs.Bool("start", false, "enable + start applianced.service when done")
	parseFlags(fs, args)

	if err := setup.SetupSystem(setup.SetupOptions{
		DataRoot: *root, DataDisk: *dataDisk, Force: *force, ForceMount: *forceMount,
		Enable: *enable, Out: os.Stdout,
	}); err != nil {
		log.Fatalf("setup-system: %v", err)
	}
}

// serve runs the daemon.
func serve(args []string) {
	fs := flag.NewFlagSet("applianced serve", flag.ExitOnError)
	root := fs.String("root", "/var/lib/glitr", "storage root directory")
	iqn := fs.String("iqn", "iqn.2026-01.dev.glitr:appliance", "target IQN")
	portals := fs.String("portals", "0.0.0.0",
		"comma-separated portals, each \"ip\" or \"ip:port\" (IPv6 bracketed when a port "+
			"is given: [fd00::1]:3260). Entries without a port use -port.")
	port := fs.Int("port", 3260, "iSCSI portal TCP port")
	listen := fs.String("listen", "127.0.0.1:8080", "REST API listen address (unauthenticated; bind to a trusted interface)")
	prInterval := fs.Duration("pr-recheck-interval", 30*time.Second,
		"how often to re-verify saved SCSI-3 PR state against the kernel (0 disables)")
	lockPath := fs.String("lock", hostlock.DefaultPath, "host-wide LIO writer lock file")
	writeBack := fs.Bool("write-back", false,
		"acknowledge writes from the page cache and advertise a volatile write cache "+
			"(WCE=1). FASTER, and NOT durable across power loss -- for development and "+
			"test targets only. Off means every write reaches stable storage before it "+
			"is acknowledged.")
	noUnmap := fs.Bool("no-unmap", false,
		"do not advertise UNMAP, so a guest cannot return space it has freed. The "+
			"backing files are sparse either way: without this the device is thin on "+
			"disk and claims to be fully provisioned on the wire, so the pool can fill "+
			"up with space nothing will ever give back. Set it only where the backing "+
			"filesystem cannot punch holes.")
	parseFlags(fs, args)

	// Check the settings BEFORE taking the host lock or touching the kernel.
	//
	// These come from flags or an environment file, and a typo in one used to
	// travel all the way to configfs before failing -- producing an error
	// about a kernel path, after the lock was held and storage was opened,
	// with the daemon never getting far enough to serve /health and explain
	// itself. Under Restart=on-failure that is a crash loop whose log says
	// nothing about the setting that caused it.
	//
	// DBRoot is discovered below rather than configured, so it is not
	// included here; appliance.Open validates the complete config again.
	parsedPortals, err := appliance.ParsePortals(*portals, uint16(*port))
	if err != nil {
		log.Fatalf("%v", err)
	}
	if err := (appliance.Config{
		TargetIQN: *iqn,
		Portals:   parsedPortals,
	}).Validate(); err != nil {
		log.Fatalf("%v", err)
	}

	lock := hostlock.New(*lockPath)
	if ok, err := lock.TryLock(); err != nil {
		log.Fatalf("lock: %v", err)
	} else if !ok {
		log.Fatalf("another LIO writer holds %s (lish mutating or a second applianced?)", lock.Path())
	}
	defer lock.Unlock()

	store, err := storage.Open(*root)
	if err != nil {
		log.Fatalf("storage: %v", err)
	}
	m := lio.New(configfs.Default())

	// Restore SCSI-3 PR reservations across a target restart. The kernel
	// persists them under db_root but never reloads them, so without this a
	// previously-fenced initiator would silently regain write access after a
	// reboot. lio replays them at backstore creation, before the LUN is
	// mapped and therefore before any I/O is possible against it.
	//
	// This is fatal rather than a warning. Not knowing where the saved state
	// lives is indistinguishable, in its consequences, from the bug being
	// fixed: volumes come up served but unreserved. Refusing to start is the
	// safe residue.
	dbRoot, err := m.DBRoot()
	if err != nil {
		log.Fatalf("cannot locate the kernel target db_root: %v\n"+
			"refusing to start: SCSI-3 PR reservations could not be restored, and serving "+
			"volumes without them would let a previously-fenced initiator write again", err)
	}
	// The kernel needs db_root/pr to exist before it can persist ANY APTPL
	// metadata: without it filp_open fails, PR OUT is answered NOT READY, and
	// the whole feature is silently inert. setup-system creates it, but a host
	// provisioned before that did not, so create it here too rather than
	// depend on a separate manual step having been run.
	if err := os.MkdirAll(filepath.Join(dbRoot, "pr"), 0o755); err != nil {
		log.Fatalf("cannot create %s: %v\n"+
			"refusing to start: the kernel cannot persist SCSI-3 PR reservations without it",
			filepath.Join(dbRoot, "pr"), err)
	}
	m.SetAPTPLRecords(appliance.APTPLProvider(dbRoot))

	cfg := appliance.Config{
		TargetIQN: *iqn,
		Portals:   parsedPortals,
		DBRoot:    dbRoot,
		WriteBack: *writeBack,
		NoUnmap:   *noUnmap,
	}
	if *writeBack {
		log.Printf("WARNING: -write-back is set: writes are acknowledged from the page cache " +
			"and are NOT durable across power loss. Volumes advertise a volatile write cache " +
			"(WCE=1), so a consumer that flushes correctly stays consistent, but anything " +
			"relying on an acknowledged write being on stable storage must not use this.")
	}
	c, err := appliance.Open(*root, store, m, cfg)
	if err != nil {
		// A damaged saved-PR file fails startup deliberately (serving a
		// volume without its reservations is the bug this guards against),
		// but the blast radius is the whole appliance, not the one volume.
		// The error names the offending path, so say what to do with it --
		// otherwise the only recovery is inferring it from the error string.
		log.Fatalf("appliance: %v\n"+
			"if this names a saved SCSI-3 PR state file, that volume's reservations cannot be "+
			"restored. Removing the named file will let the appliance start WITHOUT them, which "+
			"means anything relying on them for fencing is no longer protected.", err)
	}
	log.Printf("glitr appliance: target %s, portals %s, REST on %s", *iqn, portalList(cfg.Portals), *listen)

	// Bound every phase of a connection's life. Without these a client that
	// connects and then stops -- a half-open TCP session after a partition, a
	// stuck initiator host, a port scanner -- holds a connection and its
	// goroutine until the process restarts.
	//
	// The values are deliberately generous, because they can be: no endpoint
	// here is long-running or streaming. A volume is created with Truncate, so
	// allocation is O(1) whatever its size; a snapshot is one FICLONE; and a
	// reconcile was MEASURED at ~25ms with 200 exports. WriteTimeout is the
	// only one that could truncate a legitimate response, and there is nothing
	// for it to truncate -- but it is set well above any observed operation so
	// that stays true if one gets slower.
	srv := newRESTServer(*listen, appliance.Handler(c))

	// Periodically re-verify the saved SCSI-3 PR state against the kernel.
	//
	// Without this the warning is a cache refreshed only by an LIO-affecting
	// mutation, so on an idle appliance a condition that resolves stays
	// reported and -- worse -- one that ARISES stays invisible. Both matter
	// now that a lapsed reservation holder (a volume exported with nothing
	// protecting it) is reported.
	//
	// The check is cheap: one small file read plus one or two attribute reads
	// per backstore. It runs here rather than in the /health handler because
	// it reads configfs, which can block uncancellably in the kernel, and
	// /health must stay answerable exactly then. RecheckPR skips its tick
	// rather than queueing behind an in-flight mutation.
	stopPR := make(chan struct{})
	if *prInterval > 0 {
		go func() {
			t := time.NewTicker(*prInterval)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					c.RecheckPR()
				case <-stopPR:
					return
				}
			}
		}()
	} else {
		log.Print("NOTICE: periodic SCSI-3 PR re-verification is DISABLED; " +
			"pr_unbound in /health will only refresh on mutations that change the LIO config")
	}

	// Shutdown drains in-flight HTTP handlers, and that is what waits for a
	// reconcile: every kernel mutation happens inside a handler. There is
	// deliberately no separate reconcile barrier here.
	//
	// The drain has to be JOINED to be worth anything. Shutdown closes the
	// listener first, at which point ListenAndServe returns ErrServerClosed --
	// so without the done channel below, serve returned and the process exited
	// while Shutdown was still waiting for handlers, and the drain this
	// comment describes did not happen. A review caught that; the mechanism
	// was asserted and never exercised.
	//
	// A review also asked for a reconcile barrier, on the reading that the
	// daemon could exit mid-reconcile and leave a half-applied configfs tree.
	// MEASURED instead of argued, and the worse case was used: SIGKILL -- no
	// drain at all -- during 67 cycles of lunmap/lununmap across four volumes
	// on the lab target. After the restart, /health answered 200 ok (so the
	// kernel tree agreed with the db), the four churn volumes' backstores were
	// pruned, and the LUN set was back to baseline. Startup replay converged
	// it, which is what replay is for. That measurement is why this is a
	// correctness-of-claim fix rather than a data-loss fix.
	//
	// The remaining gap is a reconcile outrunning the 5s budget below, at
	// which point the process exits mid-write -- exactly the case SIGKILL
	// already covers. Reconcile measures ~25ms at 200 exports, so that is not
	// reachable in any configuration observed.
	//
	// The lock needs no unwinding either: hostlock is flock-based, so the
	// kernel drops it when the process dies. The measured run restarted
	// cleanly with no stale-lock recovery.
	//
	// Also checked before concluding: the one goroutine that runs OUTSIDE a
	// handler, the periodic PR re-check, is read-only (VerifyAPTPL performs no
	// configfs writes), so interrupting it cannot damage the tree.
	drained := make(chan struct{})
	stop := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		log.Print("shutting down")
		close(stopPR)
		close(stop)
	}()
	if err := runServer(srv.ListenAndServe, srv, stop, drained, 5*time.Second); err != nil {
		log.Fatal(err)
	}
}

// runServer runs serveFn until stop is closed, then shuts srv down AND WAITS
// for the drain to finish before returning.
//
// The wait is the whole point. Shutdown closes the listener first, so serveFn
// returns ErrServerClosed almost immediately while Shutdown is still waiting
// on in-flight handlers. Returning there would let the caller exit the process
// and kill the very handlers being drained -- which is what this code did
// until a review read the control flow rather than the comment above it.
//
// budget bounds the drain. Exceeding it is logged rather than returned: the
// process is going down either way, and startup replay converges a reconcile
// that was interrupted (measured -- see the comment in serve).
func runServer(serveFn func() error, srv *http.Server, stop <-chan struct{}, drained chan struct{}, budget time.Duration) error {
	go func() {
		defer close(drained)
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("WARNING: shutdown did not drain within %v (%v); a reconcile "+
				"may be interrupted and will be replayed at startup", budget, err)
		}
	}()
	if err := serveFn(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	<-drained
	return nil
}

// preflightCmd runs the read-only host readiness check.
func preflightCmd(args []string) {
	// No -root flag: the only check that used it was the reflink capability
	// probe, removed in 7e0f240 because it inspected the wrong filesystem.
	// Accepting a flag that does nothing would be worse than rejecting it.
	fs := flag.NewFlagSet("preflight", flag.ExitOnError)
	port := fs.Int("port", 3260, "iSCSI portal TCP port (checked free)")
	listen := fs.String("listen", "127.0.0.1:8080", "REST listen address (checked free / probed in -runtime)")
	runtime := fs.Bool("runtime", false, "runtime mode: probe the running appliance's health instead of checking ports free")
	parseFlags(fs, args)

	rep := setup.Preflight(setup.Options{ISCSIPort: *port, RESTListen: *listen, Runtime: *runtime})
	if rep.Fprint(os.Stdout) {
		os.Exit(1)
	}
}

// inspectCmd dumps the live LIO tree (read-only; no host lock needed).
func inspectCmd(args []string) {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	verbose := fs.Bool("v", false, "show backing devices, WWNs, every portal, and each ACL's LUN mappings")
	parseFlags(fs, args)
	cfg, err := lio.New(configfs.Default()).Discover()
	if err != nil {
		log.Fatalf("discover: %v", err)
	}

	fmt.Printf("backstores: %d, targets: %d\n", len(cfg.Backstores), len(cfg.Targets))
	m := lio.New(configfs.Default())
	for _, b := range cfg.Backstores {
		// A reservation in force is the one thing here that changes whether
		// another node can WRITE, so it is reported at both levels. Everything
		// else about a backstore is -v.
		pr := describePR(m, b)
		if !*verbose {
			if pr != "" {
				fmt.Printf("  backstore %s  %s\n", b.Name, pr)
			}
			continue
		}
		fmt.Printf("  backstore %s/%s dev=%s wwn=%s%s\n",
			b.Type, b.Name, b.Dev, b.WWN, blockSizeNote(b))
		if d := describeVolume(b); d != "" {
			fmt.Printf("      %s\n", d)
		}
		if pr != "" {
			fmt.Printf("      %s\n", pr)
		}
	}

	for _, t := range cfg.Targets {
		fmt.Printf("  target %s\n", t.IQN)
		for _, g := range t.TPGs {
			fmt.Printf("    tpg%d enable=%t portals=%s luns=%d acls=%d\n",
				g.Tag, g.Enable, portalSummary(g.Portals), len(g.LUNs), len(g.ACLs))
			if *verbose && len(g.Portals) > 0 {
				for _, p := range g.Portals {
					fmt.Printf("      portal %s%s\n", portalAddr(p), portalNote(p))
				}
			}
			for _, l := range g.LUNs {
				fmt.Printf("      lun%d -> %s\n", l.Index, l.Backstore)
			}
			for _, a := range g.ACLs {
				fmt.Printf("      acl %s (mapped %d)\n", a.InitiatorIQN, len(a.MappedLUNs))
				if !*verbose {
					continue
				}
				// What the INITIATOR sees, and what it resolves to. The two
				// numbering spaces are easy to conflate: the mapped LUN is the
				// number that initiator sees, the TPG LUN is this target's own
				// index, and they are frequently different.
				for _, ml := range a.MappedLUNs {
					mode := "rw"
					if ml.WriteProtect {
						mode = "ro"
					}
					fmt.Printf("        mapped_lun%d -> lun%d (%s) %s\n",
						ml.Index, ml.TPGLUN, lunBackstore(g, ml.TPGLUN), mode)
				}
			}
		}
	}
	reportOrphanPRState(cfg)
}

// describePR renders the live SCSI-3 reservation state of a backstore, or ""
// when there is nothing to say.
//
// Read from the kernel, not from any saved file: what is in force right now is
// the only thing that answers "can that node still write?". A read failure is
// reported rather than swallowed -- silence here would read as "no
// reservation", which is the fail-open direction.
func describePR(m *lio.Manager, b lio.Backstore) string {
	st, err := m.PRState(b)
	if err != nil {
		return "SCSI-3 PR state UNREADABLE: " + err.Error()
	}
	// Nothing registered, nothing reserved, and nothing suspicious about the
	// read: genuinely nothing to say.
	//
	// Truncated has to be part of that test. It is set when lines could not
	// be parsed, so if the kernel's format ever changes -- or the parser
	// breaks -- EVERY line is unparsable, Registrations is empty, and this
	// would return "" and print nothing at all. The one line whose job is to
	// say "do not trust this list" would be dropped in precisely the case
	// where the list is entirely untrustworthy.
	if len(st.Registrations) == 0 && st.Holder == "" && !st.Truncated {
		return ""
	}
	var sb strings.Builder
	if st.Holder != "" {
		sb.WriteString(fmt.Sprintf("RESERVED by %s", st.Holder))
		if st.Type != "" {
			sb.WriteString(" [" + st.Type + "]")
		}
	} else if len(st.Registrations) == 0 {
		// Reached only via the Truncated case above.
		sb.WriteString("registration list UNPARSABLE")
	} else {
		sb.WriteString("registered, no reservation held")
	}
	sb.WriteString(fmt.Sprintf("; %d registration(s)", len(st.Registrations)))
	for _, r := range st.Registrations {
		sb.WriteString(fmt.Sprintf("\n        key 0x%x  %s", r.Key, r.Initiator))
	}
	if st.APTPLActive {
		sb.WriteString("\n        APTPL active (persists across a target restart)")
	}
	if st.Truncated {
		sb.WriteString("\n        WARNING: the kernel's registration list was truncated or " +
			"unparsable; absence from this list does NOT mean not registered")
	}
	return sb.String()
}

// describeVolume annotates a backstore from the advisory metadata beside its
// backing file: capacity, and for a snapshot its parent.
//
// Read from the file rather than the record db so inspect keeps working with
// the daemon stopped, which is the whole reason it reads the kernel in the
// first place. Absent metadata is normal (a volume predating the file, or a
// backstore that is not ours) and says nothing rather than erroring.
func describeVolume(b lio.Backstore) string {
	v, err := storage.ReadMetadataForDisk(b.Dev)
	if err != nil {
		return ""
	}
	// Capacity comes from the LIVE fileio size, not from the metadata file.
	// metadata.json is documented advisory ("the db wins") and Resize
	// deliberately ignores its write failure, so a successful resize -- or a
	// crash-recovered grow, which never rewrites it -- can leave it stale
	// indefinitely. Discover already read the real figure out of the kernel;
	// printing the advisory one as fact is how inspect ends up contradicting
	// the device it is describing. The file is still the right source for
	// parentage and state, which the kernel does not know.
	var parts []string
	if b.Size > 0 {
		parts = append(parts, fmt.Sprintf("capacity=%s", humanBytes(b.Size)))
	} else if v.Capacity > 0 {
		parts = append(parts, fmt.Sprintf("capacity=%s (recorded)", humanBytes(v.Capacity)))
	}
	if alloc, err := allocatedBytes(b.Dev); err == nil {
		// Deliberately "allocated", never "used": a reflinked snapshot and
		// its parent SHARE extents, and each reports the full allocation, so
		// summing these across volumes double-counts. It is the right number
		// for "is this file sparse", the wrong one for "what does this cost".
		parts = append(parts, fmt.Sprintf("allocated=%s", humanBytes(alloc)))
	}
	if v.Parent != "" {
		parts = append(parts, "snapshot of "+v.Parent)
	}
	if v.State != "" && v.State != storage.Ready {
		parts = append(parts, "state="+string(v.State))
	}
	return strings.Join(parts, "  ")
}

// allocatedBytes is st_blocks * 512 -- what the filesystem has actually given
// this file, which for a sparse or reflinked file is not its length.
func allocatedBytes(path string) (int64, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, err
	}
	return st.Blocks * 512, nil
}

// humanBytes renders a byte count with a binary-prefix suffix, keeping the
// exact figure where it is not already round.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 4; m /= unit {
		div *= unit
		exp++
	}
	v := float64(n) / float64(div)
	suffix := []string{"KiB", "MiB", "GiB", "TiB", "PiB"}[exp]
	if v == float64(int64(v)) {
		return fmt.Sprintf("%d%s", int64(v), suffix)
	}
	return fmt.Sprintf("%.1f%s", v, suffix)
}

// blockSizeNote renders the logical block size an initiator sees.
//
// Called out because it is the one backstore property that changes the SHAPE
// of the device rather than its contents, it is fixed once exported, and it is
// invisible from every other line of this output.
//
// Shown under -v only, deliberately. That was raised as possibly wrong on the
// grounds that geometry matters more than most fields, and it does -- but the
// DEFAULT summary is deliberately terse, printing a backstore line at all only
// when there is a reservation condition to report. 512n is the overwhelmingly
// common case, so putting the geometry on every line would spend the summary's
// signal on a constant. An operator asking about device shape is already
// asking a -v question. fileio implements no
// get_lbppbe (linux v6.6 drivers/target/target_core_file.c:927-928), so
// physical always equals logical: this is a clean 512n or 4Kn, never 512e.
func blockSizeNote(b lio.Backstore) string {
	bs := b.Attributes["block_size"]
	switch bs {
	case "":
		// Discover only sets the key on a successful read, so an empty value
		// means the attribute could not be read -- NOT that it is the
		// default. Saying "512 (512n)" here would state a geometry on the
		// strength of a failed read, which is the same absent-vs-unreadable
		// conflation this codebase avoids elsewhere.
		return "  block=?(unreadable)"
	case "512":
		return "  block=512 (512n)"
	case "4096":
		return "  block=4096 (4Kn)"
	default:
		return "  block=" + bs
	}
}

// portalAddr renders one portal. lio.Portal.String brackets IPv6 for us, and
// is the same rendering the kernel's configfs name uses, so what is printed
// here can be pasted straight back into -portals or lish.
func portalAddr(p lio.Portal) string { return p.String() }

// portalNote says whether a portal is a wildcard or an explicit bind.
//
// This is the question an operator actually has when reading a portal list:
// binding explicitly to chosen addresses is a normal way to run a target, and
// "0.0.0.0" vs "10.0.0.5" is the difference between "reachable on everything
// this host has" and "reachable on one path". The address alone states it, but
// only if you already know to look for it.
func portalNote(p lio.Portal) string {
	switch {
	case !p.IP.IsUnspecified():
		return "  (explicit bind)"
	case p.IP.Is4():
		return "  (wildcard: every IPv4 address on this host)"
	default:
		// :: is dual-stack on a default Linux (net.ipv6.bindv6only=0), so it
		// covers IPv4 too -- which is why this does not say "every IPv6".
		return "  (wildcard: every address on this host)"
	}
}

// portalSummary is the one-line form for the TPG header: the addresses
// themselves when there are few, a count when there are many.
func portalSummary(ps []lio.Portal) string {
	if len(ps) == 0 {
		// Worth calling out rather than printing "0": a TPG with no portal
		// listens nowhere, so an enabled TPG in this state serves nobody.
		return "NONE"
	}
	if len(ps) > 3 {
		return fmt.Sprintf("%d (use -v)", len(ps))
	}
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, portalAddr(p))
	}
	return strings.Join(out, ",")
}

// lunBackstore names the backstore behind a TPG LUN index.
func lunBackstore(g lio.TPG, idx int) string {
	for _, l := range g.LUNs {
		if l.Index == idx {
			return l.Backstore
		}
	}
	// A mapped LUN pointing at a TPG LUN that does not exist is a broken
	// export, not a formatting edge case; say so rather than printing blank.
	return "MISSING TPG LUN"
}

// reportOrphanPRState lists saved SCSI-3 PR metadata with no corresponding
// backstore. See appliance.OrphanPRState for the full rationale, including
// why these are reported rather than reaped.
//
// This is the operator-facing view; applianced also logs the condition once
// at startup, so it is not only visible to someone who thinks to run
// `inspect`. It keys off the DISCOVERED backstores rather than the volume
// db, so it stays useful even when the daemon is not running.
func reportOrphanPRState(cfg lio.Config) {
	dbRoot, err := lio.New(configfs.Default()).DBRoot()
	if err != nil {
		return
	}
	var live []string
	for _, b := range cfg.Backstores {
		if b.WWN != "" {
			live = append(live, b.WWN)
		}
	}
	orphans, err := appliance.OrphanPRState(dbRoot, live)
	if err != nil {
		fmt.Printf("\ncannot check for orphaned SCSI-3 PR state: %v\n", err)
		return
	}
	if len(orphans) == 0 {
		return
	}
	fmt.Printf("\nsaved SCSI-3 PR metadata with no matching backstore: %d\n", len(orphans))
	for _, o := range orphans {
		fmt.Printf("  %s\n", o)
	}
	fmt.Print("these are inert (only read back for a backstore with the same WWN) and are NOT\n" +
		"removed automatically: a volume can be absent temporarily (a partially restored db,\n" +
		"a backstore not yet replayed) and reaping would destroy live fencing state.\n" +
		"Remove them only if those volumes are really gone.\n")
}

// portalList renders portals for the startup log.
//
// Not "%v:%d" over a slice, which is what this used to be: that printed
// "[fd00::1 10.0.0.1]:3260" -- one port stapled onto a list, the same untruth
// the Config type used to encode.
func portalList(ps []lio.Portal) string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, portalAddr(p))
	}
	return strings.Join(out, ",")
}

// parseFlags parses args and refuses anything left over.
//
// flag.Parse stops at the first non-flag argument and leaves the rest in
// Args(), which every subcommand used to discard. Nothing here takes a
// positional argument, so a leftover is always a mistake -- and a SILENT one,
// which is the problem.
//
// MEASURED on the lab: `-portals 10.10.0.1:3260 10.10.0.11:3260`, a space
// where a comma belongs, started the daemon "active" serving exactly ONE
// portal. The second was parsed as a positional argument and dropped without
// a word. Multipath needs both, so the operator gets half a fabric and no
// signal that anything was wrong. A trailing comma is caught (it produces an
// empty portal), but a space is not, because the value never reaches
// Config.Validate to be checked.
//
// flag.ExitOnError already handles an unknown FLAG. This closes the other
// half, which nothing else can: by the time a stray word has been split off,
// no downstream validation can tell it was ever meant to be part of a value.
func parseFlags(fs *flag.FlagSet, args []string) {
	_ = fs.Parse(args)
	if err := extraArgsError(fs); err != nil {
		log.Fatalf("%v", err)
	}
}

// extraArgsError reports leftover positional arguments. Split out from
// parseFlags so the rule can be tested: log.Fatalf exits the process, which a
// test cannot observe.
func extraArgsError(fs *flag.FlagSet) error {
	if fs.NArg() == 0 {
		return nil
	}
	return fmt.Errorf("%s: unexpected argument %q -- this command takes no positional "+
		"arguments, so it is usually a flag value split by a space (a portal list "+
		"must be comma-separated with no spaces: -portals a:3260,b:3260)",
		fs.Name(), fs.Arg(0))
}

// newRESTServer builds the REST listener with every phase of a connection's
// life bounded.
//
// Split out of serve so the behaviour can be tested: without these a client
// that connects and then stops -- a half-open TCP session after a partition, a
// stuck initiator host, a port scanner -- holds a connection and its goroutine
// until the process restarts.
//
// The values are deliberately generous, because they can be: no endpoint here
// is long-running or streaming. A volume is created with Truncate, so
// allocation is O(1) whatever its size; a snapshot is one FICLONE; and a
// reconcile was MEASURED at ~25ms with 200 exports. WriteTimeout is the only
// one that could truncate a legitimate response, and there is nothing here for
// it to truncate -- it is set far above any observed operation so that stays
// true if one gets slower.
func newRESTServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}
