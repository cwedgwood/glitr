// Package setup provides the appliance host-preparation tooling: distro
// detection, a read-only preflight readiness check, and an idempotent
// setup-system that makes a fresh host able to run applianced.
//
// Unlike the daemon's serve path (which shells out to nothing), this package
// is one-time provisioning tooling and legitimately runs external commands
// (modprobe, mount, mkfs.xfs, systemctl) — it is not on the data path.
package setup

import (
	"os"
	"strings"
)

// Distro identifies the host OS enough to give correct, copy-pasteable
// remediation and to drive setup-system's package/module choices.
type Distro struct {
	ID      string // os-release ID, e.g. "debian", "azurelinux"
	Version string // VERSION_ID
	Pretty  string // PRETTY_NAME
}

// Detect reads /etc/os-release. An unreadable/absent file yields ID "unknown".
func Detect() Distro {
	d := Distro{ID: "unknown"}
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return d
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, "\"")
		switch k {
		case "ID":
			d.ID = v
		case "VERSION_ID":
			d.Version = v
		case "PRETTY_NAME":
			d.Pretty = v
		}
	}
	return d
}

// Supported reports whether setup-system knows how to prepare this distro.
// preflight still runs on any distro (with generic remediation).
func (d Distro) Supported() bool {
	switch d.ID {
	case "debian", "ubuntu", "azurelinux", "mariner":
		return true
	}
	return false
}

// pkgMgrInstall returns the package-install command prefix for this distro.
func (d Distro) pkgMgrInstall() string {
	switch d.ID {
	case "debian", "ubuntu":
		return "apt-get install -y"
	case "azurelinux", "mariner":
		return "tdnf install -y"
	default:
		return "<install>"
	}
}

// InstallHint returns a copy-pasteable command to install pkgs on this distro.
func (d Distro) InstallHint(pkgs ...string) string {
	return d.pkgMgrInstall() + " " + strings.Join(pkgs, " ")
}

// Pkg maps a logical capability to this distro's package name (or "" if it
// needs no package on this distro).
//
// Capabilities: "xfsprogs" (mkfs.xfs), "lio-modules" (the kernel target
// modules if not already in the base kernel), "iscsi-initiator".
//
// The Azure Linux (3.0) names were verified live on a customized minimal-os
// VM (2026-07-28): the LIO target modules (target_core_mod, iscsi_target_mod,
// target_core_file) ship in the stock "kernel" package — no separate
// kernel-modules package — so "lio-modules" needs no install, same as Debian.
// xfsprogs is not installed by default (tdnf install xfsprogs); targetcli is
// not packaged on AL3 at all, so there is no conflicting boot writer to mask.
func (d Distro) Pkg(capability string) string {
	switch d.ID {
	case "azurelinux", "mariner":
		switch capability {
		case "lio-modules":
			return "" // in the stock AL3 kernel package (verified on AL3 3.0)
		case "iscsi-initiator":
			return "iscsi-initiator-utils"
		default:
			return capability // xfsprogs
		}
	default: // debian/ubuntu
		switch capability {
		case "lio-modules":
			return "" // in the stock linux-image kernel
		case "iscsi-initiator":
			return "open-iscsi"
		default:
			return capability // xfsprogs
		}
	}
}
