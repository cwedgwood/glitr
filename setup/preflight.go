package setup

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"time"
)

// Severity classifies a failed check.
type Severity int

const (
	// SevOK: the check passed.
	SevOK Severity = iota
	// SevWarn: degraded but the appliance can still run.
	SevWarn
	// SevFatal: the appliance cannot run until this is fixed.
	SevFatal
)

func (s Severity) String() string {
	switch s {
	case SevWarn:
		return "WARN"
	case SevFatal:
		return "FATAL"
	default:
		return "OK"
	}
}

// Check is one preflight result.
type Check struct {
	Name   string
	Passed bool
	Sev    Severity // severity IF not passed
	Detail string   // what was found and, on failure, how to fix it
}

// Report is the full preflight result.
type Report struct {
	Distro Distro
	Checks []Check
}

// Failed reports whether any FATAL check did not pass.
func (r Report) Failed() bool {
	for _, c := range r.Checks {
		if !c.Passed && c.Sev == SevFatal {
			return true
		}
	}
	return false
}

// Fprint writes a human-readable report. Returns whether it failed (any FATAL).
func (r Report) Fprint(w interface{ Write([]byte) (int, error) }) bool {
	fmt.Fprintf(w, "preflight — %s\n", r.Distro.Pretty)
	warn := 0
	for _, c := range r.Checks {
		status := "OK"
		if !c.Passed {
			status = c.Sev.String()
			if c.Sev == SevWarn {
				warn++
			}
		}
		fmt.Fprintf(w, "  [%-5s] %-24s %s\n", status, c.Name, c.Detail)
	}
	failed := r.Failed()
	switch {
	case failed:
		fmt.Fprintln(w, "\nRESULT: NOT READY — resolve the FATAL items above (setup-system fixes most).")
	case warn > 0:
		fmt.Fprintf(w, "\nRESULT: READY with %d warning(s).\n", warn)
	default:
		fmt.Fprintln(w, "\nRESULT: READY.")
	}
	return failed
}

// Options configures preflight/setup to the intended deployment.
type Options struct {
	ISCSIPort  int    // iSCSI portal port (3260)
	RESTListen string // REST listen address (host:port)
	Runtime    bool   // runtime mode: probe the running appliance's health
	// instead of checking the ports are free (they are owned by the appliance)
}

// lioModules are the kernel target modules the appliance needs.
var lioModules = []string{"target_core_mod", "iscsi_target_mod", "target_core_file"}

// conflictingUnits are targetcli's systemd writers; if active they fight the
// appliance for ownership of the single kernel LIO tree.
var conflictingUnits = []string{"target.service", "rtslib-fb-targetctl.service"}

const configfsTarget = "/sys/kernel/config/target"

// Preflight runs the read-only readiness checks for opts and returns a Report.
func Preflight(opts Options) Report {
	d := Detect()
	r := Report{Distro: d}
	add := func(name string, passed bool, sev Severity, detail string) {
		r.Checks = append(r.Checks, Check{name, passed, sev, detail})
	}

	// 1. Root — configfs writes need CAP_SYS_ADMIN.
	if os.Geteuid() == 0 {
		add("root", true, SevFatal, "running as root")
	} else {
		add("root", false, SevFatal, "must run as root (configfs writes need CAP_SYS_ADMIN)")
	}

	// 2. Known distro (informational for setup-system).
	if d.Supported() {
		add("distro", true, SevWarn, d.Pretty)
	} else {
		add("distro", false, SevWarn, fmt.Sprintf("unrecognised distro %q — setup-system is unsupported here; preflight guidance is generic", d.ID))
	}

	// 3. LIO kernel modules — loaded, or at least available to load.
	for _, m := range lioModules {
		switch {
		case moduleLoaded(m):
			add("module:"+m, true, SevFatal, "loaded")
		case moduleAvailable(m):
			add("module:"+m, true, SevFatal, "available (setup-system will load it)")
		default:
			fix := "kernel target modules are missing"
			if pkg := d.Pkg("lio-modules"); pkg != "" {
				fix += "; install: " + d.InstallHint(pkg)
			}
			add("module:"+m, false, SevFatal, fix)
		}
	}

	// 4. configfs mounted (setup-system can mount it if not).
	if mounted(configfsRoot()) {
		add("configfs", true, SevWarn, "mounted at "+configfsRoot())
	} else {
		add("configfs", false, SevWarn, "not mounted; setup-system mounts it (mount -t configfs none "+configfsRoot()+")")
	}

	// 5. iSCSI fabric group (a makable configfs group, not auto-created).
	if _, err := os.Stat(configfsTarget + "/iscsi"); err == nil {
		add("iscsi-fabric", true, SevWarn, "present")
	} else {
		add("iscsi-fabric", false, SevWarn, "missing; setup-system creates it (mkdir "+configfsTarget+"/iscsi)")
	}

	// 6. db_root/pr — where LIO persists SCSI-3 PR APTPL metadata. The kernel
	// does not create it; without it PR registrations return NOT READY and
	// reservations do not survive a target restart (they still apply in RAM,
	// so the breakage is silent).
	if _, err := os.Stat("/var/target/pr"); err == nil {
		add("pr-aptpl-dir", true, SevWarn, "/var/target/pr present (PR reservations persist across restart)")
	} else {
		add("pr-aptpl-dir", false, SevWarn, "/var/target/pr missing; SCSI-3 PR registrations will fail with NOT READY and will not persist. setup-system creates it")
	}

	// 7. No conflicting targetcli writer active.
	for _, u := range conflictingUnits {
		if unitActive(u) {
			add("conflict:"+u, false, SevFatal, "active — a competing LIO writer; setup-system masks it (systemctl mask "+u+")")
		} else {
			add("conflict:"+u, true, SevFatal, "not active")
		}
	}

	// 8. Ports (capability mode) or health (runtime mode).
	if opts.Runtime {
		// The appliance owns 3260 + REST; probe it is actually serving.
		if url := healthURL(opts.RESTListen); url != "" {
			if ok, detail := httpHealthy(url); ok {
				add("appliance-health", true, SevFatal, detail)
			} else {
				add("appliance-health", false, SevFatal, detail)
			}
		}
	} else {
		if opts.ISCSIPort != 0 {
			checkPort(add, "port:iscsi", fmt.Sprintf(":%d", opts.ISCSIPort),
				func() string { return kernelTargetHolds(opts.ISCSIPort) })
		}
		if opts.RESTListen != "" {
			checkPort(add, "port:rest", opts.RESTListen,
				func() string { return applianceHolds(opts.RESTListen) })
		}
	}

	return r
}

// kernelTargetHolds reports how the kernel LIO target is using port, or "" if
// it is not. The portals are directories named "<ip>:<port>" under each TPG's
// np/, IPv6 bracketed, so this is positive identification rather than a guess
// about who might plausibly hold a well-known port.
func kernelTargetHolds(port int) string {
	iqns, err := os.ReadDir(configfsRoot() + "/target/iscsi")
	if err != nil {
		return ""
	}
	suffix := fmt.Sprintf(":%d", port)
	var portals []string
	for _, iqn := range iqns {
		tpgs, err := os.ReadDir(configfsRoot() + "/target/iscsi/" + iqn.Name())
		if err != nil {
			continue
		}
		for _, tpg := range tpgs {
			if !strings.HasPrefix(tpg.Name(), "tpgt_") {
				continue
			}
			nps, err := os.ReadDir(configfsRoot() + "/target/iscsi/" + iqn.Name() + "/" + tpg.Name() + "/np")
			if err != nil {
				continue
			}
			for _, np := range nps {
				if strings.HasSuffix(np.Name(), suffix) {
					portals = append(portals, np.Name())
				}
			}
		}
	}
	if len(portals) == 0 {
		return ""
	}
	return fmt.Sprintf("the kernel LIO target, on %s", strings.Join(portals, ", "))
}

// applianceHolds reports whether a healthy appliance is answering on listen,
// which identifies the holder of the REST port as this appliance rather than
// something unrelated.
func applianceHolds(listen string) string {
	url := healthURL(listen)
	if url == "" {
		return ""
	}
	if ok, _ := httpHealthy(url); ok {
		return "a running appliance, answering /health"
	}
	return ""
}

// healthURL turns a listen address (host:port) into a /health URL, mapping a
// wildcard bind to the loopback address OF THE SAME FAMILY.
//
// Both parts used to be done by matching text: "0.0.0.0" or "::" meant
// wildcard, and either became 127.0.0.1. That missed every other spelling of
// the unspecified address, and on an IPv6-only host -- which this appliance
// supports -- it produced a v4 loopback URL that cannot be reached. Asking the
// address whether it is unspecified, and which family it is, gets both right
// without enumerating spellings.
func healthURL(listen string) string {
	if listen == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return ""
	}
	// An empty host is Go's "listen on everything", and net/http defaults to
	// IPv4 loopback for it.
	loopback := "127.0.0.1"
	if addr, err := netip.ParseAddr(host); err == nil {
		if !addr.IsUnspecified() {
			loopback = ""
		} else if addr.Is6() && !addr.Is4In6() {
			loopback = "::1"
		}
	} else if host != "" {
		loopback = "" // a hostname: use it as given
	}
	if loopback != "" {
		host = loopback
	}
	// "/v1/health", spelled out rather than imported: the layering rule is
	// that setup depends on nothing else in this module (CI enforces it), so
	// this cannot reference appliance.APIPrefix. If the prefix ever moves,
	// preflight reports the appliance as unreachable, which is loud.
	return "http://" + net.JoinHostPort(host, port) + "/v1/health"
}

func httpHealthy(url string) (bool, string) {
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return false, "appliance not responding at " + url + ": " + err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return true, "REST healthy at " + url
	}
	return false, fmt.Sprintf("appliance at %s returned HTTP %d", url, resp.StatusCode)
}

// checkPort reports whether addr can be served. heldBy is consulted only when
// the bind fails because the address is already in use: it returns a
// description of the holder if that holder is the expected one, else "".
//
// The distinction matters because "in use" is the NORMAL state of both of this
// appliance's ports once it is running -- 3260 by the kernel target, REST by
// the daemon itself -- and reporting that as FATAL made `applianced preflight`
// answer NOT READY, exit 1, on a perfectly healthy host that was serving
// volumes at that moment. A diagnostic that cries wolf on a working system is
// worse than none: it is the one people learn to ignore, and it was reachable
// by simply running the obvious command on the obvious machine.
//
// Only EADDRINUSE takes this path. A bind refused for any other reason --
// permission, a bad address, an interface that does not exist -- is still a
// fault and is still reported as one.
func checkPort(add func(string, bool, Severity, string), name, addr string, heldBy func() string) {
	// A bare port ("3260") becomes ":3260". Decided by trying to split rather
	// than by looking for a colon: an unbracketed IPv6 address is full of
	// colons and would have been passed through unchanged, then failed to
	// bind for a reason that had nothing to do with the port being in use.
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = ":" + addr
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		if errors.Is(err, syscall.EADDRINUSE) && heldBy != nil {
			if who := heldBy(); who != "" {
				add(name, true, SevFatal, addr+" is in use, by "+who)
				return
			}
		}
		add(name, false, SevFatal, addr+" is not bindable: "+err.Error())
		return
	}
	_ = ln.Close()
	add(name, true, SevFatal, addr+" is free")
}

// --- probes (setup tooling may shell out; the daemon serve path never does) ---

func configfsRoot() string { return "/sys/kernel/config" }

func moduleLoaded(name string) bool {
	_, err := os.Stat("/sys/module/" + name)
	return err == nil
}

func moduleAvailable(name string) bool {
	// modinfo resolves a module in /lib/modules/<uname -r> without loading it.
	return command("modinfo", "-F", "filename", name).Run() == nil
}

func mounted(path string) bool { return mountSource(path) != "" }

// mountSource returns the device currently mounted at path, or "" if nothing
// is mounted there. The last matching /proc/mounts entry wins, which is what
// the kernel resolves for stacked mounts.
func mountSource(path string) string {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return ""
	}
	src := ""
	for line := range strings.SplitSeq(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[1] == path {
			src = f[0]
		}
	}
	return src
}

func unitActive(unit string) bool {
	// systemctl is-active exits 0 and prints "active" when active.
	out, _ := command("systemctl", "is-active", unit).Output()
	return strings.TrimSpace(string(out)) == "active"
}
