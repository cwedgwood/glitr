package setup

import (
	"embed"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

//go:embed assets/modules-load.conf assets/applianced.service
var assets embed.FS

// SetupOptions configures setup-system.
type SetupOptions struct {
	DataRoot   string // where the XFS data disk is mounted (e.g. /var/lib/glitr)
	DataDisk   string // block device to format XFS + mount at DataRoot (optional)
	Force      bool   // allow mkfs over a device that already has a filesystem
	ForceMount bool   // allow mounting the data disk over a NON-EMPTY data root
	Enable     bool   // enable + start applianced.service at the end
	Out        io.Writer
}

// SetupSystem idempotently prepares the host to run applianced: loads the LIO
// modules (and persists them), mounts configfs, creates the db_root and iSCSI
// fabric group, masks the conflicting targetcli units, optionally formats and
// mounts an XFS data disk, and installs the systemd unit. Supported on
// Debian/Ubuntu and Azure Linux; refuses on an unrecognised distro.
func SetupSystem(opts SetupOptions) error {
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("setup-system must run as root")
	}
	d := Detect()
	if !d.Supported() {
		return fmt.Errorf("setup-system does not support %q (%s); supported: debian, ubuntu, azurelinux", d.ID, d.Pretty)
	}
	step := func(format string, a ...any) { fmt.Fprintf(opts.Out, "==> "+format+"\n", a...) }

	// 1. Load the LIO modules now, and persist them for boot.
	step("loading kernel LIO modules: %s", strings.Join(lioModules, " "))
	for _, m := range lioModules {
		if !moduleLoaded(m) {
			if err := run("modprobe", m); err != nil {
				return fmt.Errorf("modprobe %s: %w (install: %s)", m, err, d.InstallHint(d.Pkg("lio-modules")))
			}
		}
	}
	if err := installAsset("assets/modules-load.conf", "/etc/modules-load.d/glitr.conf", 0o644); err != nil {
		return err
	}

	// 2. configfs (systemd usually auto-mounts it; make sure).
	if !mounted(configfsRoot()) {
		step("mounting configfs at %s", configfsRoot())
		if err := os.MkdirAll(configfsRoot(), 0o755); err != nil {
			return err
		}
		if err := run("mount", "-t", "configfs", "none", configfsRoot()); err != nil {
			return fmt.Errorf("mount configfs: %w", err)
		}
	}

	// 3. db_root and the makable iSCSI fabric group (not auto-created).
	//
	// db_root/pr is where LIO persists SCSI-3 Persistent Reservation APTPL
	// metadata (aptpl_<wwn>). The kernel does NOT create it: filp_open fails
	// and the PR OUT is answered with NOT READY / "Logical unit communication
	// failure" even though the registration is applied in memory, so
	// reservations silently do not survive a target restart.
	step("creating /var/target (+pr) and %s/iscsi", configfsTarget)
	if err := os.MkdirAll("/var/target/pr", 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(configfsTarget+"/iscsi", 0o755); err != nil {
		return fmt.Errorf("mkdir %s/iscsi: %w (are the LIO modules loaded?)", configfsTarget, err)
	}

	// 4. Mask the targetcli boot writers (idempotent; harmless if absent).
	step("masking conflicting targetcli units")
	_ = run("systemctl", append([]string{"mask"}, conflictingUnits...)...)

	// 5. Data disk (optional): format XFS + mount + persist in fstab.
	if opts.DataRoot != "" {
		if err := os.MkdirAll(opts.DataRoot, 0o755); err != nil {
			return err
		}
	}
	if opts.DataDisk != "" {
		if err := setupDataDisk(step, opts); err != nil {
			return err
		}
	}

	// 6. Install the systemd unit + a default env file.
	step("installing systemd unit /etc/systemd/system/applianced.service")
	if err := installAsset("assets/applianced.service", "/etc/systemd/system/applianced.service", 0o644); err != nil {
		return err
	}
	if err := writeEnvFile(opts); err != nil {
		return err
	}
	if err := run("systemctl", "daemon-reload"); err != nil {
		return err
	}

	if opts.Enable {
		step("enabling + starting applianced.service")
		if err := run("systemctl", "enable", "--now", "applianced.service"); err != nil {
			return err
		}
	} else {
		step("done — start with: systemctl enable --now applianced")
	}
	return nil
}

// setupDataDisk formats (if empty or --force) and mounts the data disk, and
// adds an fstab entry so the mount survives reboot.
func setupDataDisk(step func(string, ...any), opts SetupOptions) error {
	dev, root := opts.DataDisk, opts.DataRoot
	d := Detect()
	if err := d.ensureTool(step, "mkfs.xfs", d.Pkg("xfsprogs")); err != nil {
		return err
	}
	fstype, ferr := blkidValue(dev, "TYPE")
	if ferr != nil && !opts.Force {
		return fmt.Errorf("cannot probe %s for an existing filesystem: %w (use -force to format anyway)", dev, ferr)
	}
	switch {
	case fstype == "xfs":
		step("data disk %s already XFS; keeping it", dev)
	case fstype == "" || opts.Force:
		step("formatting %s as XFS", dev)
		if err := run("mkfs.xfs", "-f", dev); err != nil {
			return fmt.Errorf("mkfs.xfs %s: %w", dev, err)
		}
	default:
		return fmt.Errorf("%s already has a %s filesystem; refusing to format (use -force to override)", dev, fstype)
	}
	if !mounted(root) {
		if err := checkMountTarget(root, dev, opts.ForceMount); err != nil {
			return err
		}
		step("mounting %s at %s", dev, root)
		if err := run("mount", dev, root); err != nil {
			return fmt.Errorf("mount %s %s: %w", dev, root, err)
		}
	} else if src := mountSource(root); src != "" && src != dev {
		// Something else is already mounted here. Writing an fstab entry for
		// the requested device would silently switch the appliance to a
		// different filesystem on the next boot.
		return fmt.Errorf("%s is already mounted from %s, not %s; refusing to write an fstab entry "+
			"that would change it on next boot", root, src, dev)
	}
	// Persist in fstab by UUID.
	//
	// nofail, because a data disk that does not appear must not take the whole
	// machine to an emergency shell. `defaults` makes the entry part of
	// local-fs.target, so a missing or reformatted disk fails the target, and
	// systemd drops to a root password prompt on the console -- on a headless
	// appliance that is indistinguishable from a dead machine, and it is
	// reachable by ordinary means: replacing the disk, or repartitioning the
	// host underneath it (MEASURED, exactly that way, on the lab target).
	//
	// The daemon is ordered After= this mount and RequiresMountsFor= it (see
	// below), so nofail does not mean it starts on the empty directory
	// underneath: applianced simply does not start, which is the correct
	// outcome and leaves an operator a machine they can log into to fix it.
	// x-systemd.device-timeout bounds the wait for a device that never shows
	// up, rather than hanging boot for the default 90s.
	uuid, err := blkidValue(dev, "UUID")
	if err != nil || uuid == "" {
		return fmt.Errorf("could not read UUID of %s: %v", dev, err)
	}
	line := fmt.Sprintf("UUID=%s %s xfs nofail,x-systemd.device-timeout=10s 0 0", uuid, root)
	replaced, err := ensureFstab(fstabPath, line, root)
	if err != nil {
		return err
	}
	if replaced {
		step("fstab entry written (UUID=%s -> %s)", uuid, root)
	} else {
		step("fstab entry already correct (UUID=%s -> %s)", uuid, root)
	}
	// Order the daemon after this mount so a boot-time race cannot start it on
	// the underlying (empty) directory before the disk mounts over it.
	if err := writeMountDropin(root); err != nil {
		return err
	}
	return nil
}

// writeMountDropin installs a systemd drop-in adding RequiresMountsFor for the
// data root, so applianced is ordered after the data-disk mount at boot.
func writeMountDropin(root string) error {
	dir := "/etc/systemd/system/applianced.service.d"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	content := "# installed by `applianced setup-system -data-disk`\n" +
		"[Unit]\nRequiresMountsFor=" + root + "\n"
	return os.WriteFile(filepath.Join(dir, "10-datamount.conf"), []byte(content), 0o644)
}

// checkMountTarget refuses to mount dev over a data root that already holds
// something, unless explicitly overridden.
//
// Mounting over a non-empty directory HIDES its contents rather than deleting
// them, which to an operator is indistinguishable from data loss: the volumes
// are gone from every listing, and the only way back is to unmount. It bites in
// the out-of-order path -- bare setup, create volumes, then add -data-disk
// later. The recommended order (data disk at setup, before any volume exists)
// never reaches it.
//
// Deliberately NOT tied to -force: -force authorises wiping the DEVICE, which
// is a different decision from hiding an existing data root behind a new mount.
// Conflating them would disable this guard in exactly the aggressive-
// reprovision case it exists for. -force-mount is the explicit override.
//
// Split out from SetupSystem so it can be tested: SetupSystem needs root, a
// spare block device and a distro package manager, so nothing exercised this
// guard, and an unreadable directory returning nil here would have been
// invisible.
func checkMountTarget(root, dev string, forceMount bool) error {
	entries, err := os.ReadDir(root)
	switch {
	case err != nil && !os.IsNotExist(err):
		// Could not tell. Refuse: "I could not read it" must not take the same
		// path as "it is empty".
		return fmt.Errorf("cannot check whether %s is empty before mounting %s: %w "+
			"(use -force-mount to override)", root, dev, err)
	case len(entries) > 0 && !forceMount:
		return fmt.Errorf("%s is not empty; mounting %s over it would hide the existing data "+
			"(migrate or empty it, or use -force-mount to override)", root, dev)
	}
	return nil
}

// ensureTool makes sure `tool` is on PATH, installing pkg via the distro
// package manager if not. A one-command host-prep flow should not require the
// operator to pre-install helper packages.
func (d Distro) ensureTool(step func(string, ...any), tool, pkg string) error {
	if _, err := exec.LookPath(tool); err == nil {
		return nil
	}
	if pkg == "" {
		return fmt.Errorf("%s not found and no package known to install it on %s", tool, d.ID)
	}
	step("installing %s (provides %s)", pkg, tool)
	if err := d.installPackages(pkg); err != nil {
		return fmt.Errorf("install %s: %w (try manually: %s)", pkg, err, d.InstallHint(pkg))
	}
	if _, err := exec.LookPath(tool); err != nil {
		return fmt.Errorf("%s still not found after installing %s", tool, pkg)
	}
	return nil
}

// installPackages installs pkgs with the distro's package manager.
func (d Distro) installPackages(pkgs ...string) error {
	switch d.ID {
	case "debian", "ubuntu":
		_ = run("apt-get", "update") // best-effort refresh; ignore transient failures
		return run("apt-get", append([]string{"install", "-y"}, pkgs...)...)
	case "azurelinux", "mariner":
		return run("tdnf", append([]string{"install", "-y"}, pkgs...)...)
	default:
		return fmt.Errorf("no package manager known for %s", d.ID)
	}
}

// --- helpers ---

// command builds a command for an external program with the C locale forced,
// so anything it prints is the same text on every host.
//
// Measured, rather than assumed: on a host with fr_FR.UTF-8 generated, parted
// and xfs_repair
// render strerror in the host language while ip and systemctl do not, because
// glibc only translates once a program calls setlocale(LC_ALL, ""). Which
// tools do is not knowable from here and changes between distributions, so the
// locale is pinned rather than surveyed.
//
// This is what makes generating a locale on appliance hosts unnecessary:
// unitActive compares systemctl's output to the literal "active" and setup's
// failures quote a tool's diagnostic, and both are now fixed by construction
// instead of by how the host happens to be provisioned.
//
// LANGUAGE is cleared too -- it is a gettext extension that overrides LC_ALL
// for message translation, so clearing LC_ALL alone is not enough.
func command(name string, args ...string) *exec.Cmd {
	c := exec.Command(name, args...)
	c.Env = append(os.Environ(), "LC_ALL=C", "LANGUAGE=")
	return c
}

func run(name string, args ...string) error {
	cmd := command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func installAsset(assetPath, dst string, mode os.FileMode) error {
	data, err := assets.ReadFile(assetPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, data, mode)
}

func writeEnvFile(opts SetupOptions) error {
	root := opts.DataRoot
	if root == "" {
		root = "/var/lib/glitr"
	}
	// Default args; the operator edits this file to tune iqn/portals/listen.
	env := fmt.Sprintf("# glitr applianced flags (edit to taste; the REST API is unauthenticated)\nGLITR_ARGS=-root %s -listen 127.0.0.1:8080\n", root)
	if err := os.MkdirAll("/etc/glitr", 0o755); err != nil {
		return err
	}
	// Do not clobber an existing operator-tuned env file.
	if _, err := os.Stat("/etc/glitr/applianced.env"); err == nil {
		return nil
	}
	return os.WriteFile("/etc/glitr/applianced.env", []byte(env), 0o644)
}

// blkidValue returns a blkid field (TYPE, UUID) for dev. A field that is
// simply unset (blkid exit status 2, "nothing detected") yields ("", nil); a
// genuine probe failure (blkid missing, I/O/permission error) yields a
// non-nil error — so a caller never mistakes "could not probe" for "no
// filesystem" and force-formats a disk that actually holds data.
func blkidValue(dev, field string) (string, error) {
	out, err := command("blkid", "-s", field, "-o", "value", dev).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 2 {
			return "", nil // blkid: nothing detected for this field
		}
		return "", fmt.Errorf("blkid %s %s: %w", field, dev, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// fstabPath is the file ensureFstab converges. A constant rather than a
// literal so tests can exercise the real function against a temp file: the
// duplicate-entry bug below shipped precisely because this code could only be
// tested by running it as root on a real machine, so it never was.
const fstabPath = "/etc/fstab"

// ensureFstab makes /etc/fstab describe exactly one entry for mountpoint,
// replacing any stale entry for the same path and reporting whether it
// changed anything.
//
// Keying on the MOUNT POINT rather than the UUID is deliberate, and the
// distinction is not academic. This used to skip only when it found the same
// UUID, so re-running against a reformatted disk -- which necessarily has a
// new UUID -- appended a second entry for the same mount point while the
// first still named a filesystem that no longer existed. systemd generates
// one mount unit per mount point, so two entries for one path is never right:
// it logs a duplicate and takes one, and the machine's behaviour then depends
// on which. MEASURED on the lab target 2026-08-08, where a reset data disk
// left `UUID=736e1872-... /var/lib/glitr` behind, var-lib-glitr.mount failed,
// and applianced failed with it reporting only "Dependency failed" -- naming
// neither fstab nor the disk.
//
// Comments and unrelated entries are preserved byte-for-byte. Only lines
// whose mount-point field matches are removed.
func ensureFstab(path, line, mountpoint string) (changed bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	var keep []string
	var found bool
	for l := range strings.SplitSeq(string(data), "\n") {
		if t := strings.TrimSpace(l); t == "" || strings.HasPrefix(t, "#") {
			keep = append(keep, l)
			continue
		}
		f := strings.Fields(l)
		if len(f) >= 2 && f[1] == mountpoint {
			found = true
			if strings.Join(f, " ") == line {
				keep = append(keep, l) // already exactly right
				continue
			}
			continue // stale or differing: drop it, the new line replaces it
		}
		keep = append(keep, l)
	}
	if found && slices.Contains(keep, line) {
		return false, nil
	}
	// Trailing empty element from a final newline: put the entry before it so
	// the file keeps exactly one terminating newline.
	if n := len(keep); n > 0 && strings.TrimSpace(keep[n-1]) == "" {
		keep = slices.Insert(keep, n-1, line)
	} else {
		keep = append(keep, line, "")
	}
	out := strings.Join(keep, "\n")

	// Write via a temp file + rename so a crash cannot leave a truncated
	// fstab, which would cost the machine its root mount options at best.
	tmp := path + ".glitr.tmp"
	if err := os.WriteFile(tmp, []byte(out), 0o644); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return false, err
	}
	return true, nil
}
