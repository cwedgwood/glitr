package lio

import "net/netip"

// The object model mirrors the kernel LIO configfs hierarchy. Each
// struct holds only the properties needed to describe kernel state; no
// appliance concepts (volumes, snapshots, databases, allocation policy)
// appear here.

// DefaultPortalPort is the standard iSCSI portal port.
const DefaultPortalPort = 3260

// BackstoreType enumerates supported core backstore plugins.
type BackstoreType string

const (
	// FileIO is the fileio backstore plugin (file-backed).
	FileIO BackstoreType = "fileio"
	// IBlock is the iblock backstore plugin (block-device-backed).
	IBlock BackstoreType = "iblock"
)

// Backstore is a core storage object under core/<plugin>_<hba>/<name>.
//
// The library does not create the backing file/device (that is an
// appliance responsibility); it only wires an existing path into the
// kernel.
type Backstore struct {
	Type BackstoreType `json:"type"`
	// HBA is the host-bus-adapter index, forming the directory
	// core/<plugin>_<HBA>. It is part of a backstore's identity (two
	// objects with the same name under different HBAs are distinct). The
	// kernel permits multiple storage objects to share one HBA directory;
	// the appliance nonetheless assigns a distinct HBA per backstore so
	// each can be torn down (and its HBA dir reclaimed) independently.
	HBA int `json:"hba"`
	// Name is the storage object name (directory under the HBA).
	Name string `json:"name"`
	// Dev is the backing file (fileio) or block device (iblock) path.
	Dev string `json:"dev"`
	// BufferedIO selects the fileio backend's buffered mode: the backing file
	// is opened WITHOUT O_DSYNC, so writes land in the page cache and are
	// acknowledged before they reach stable storage.
	//
	// CREATE-TIME ONLY. It is part of the control string, which the kernel
	// consumes when the object is configured; there is no attribute to change
	// it afterwards, so switching modes means destroying and recreating the
	// backstore (and therefore unexporting the volume).
	//
	// The kernel couples this to the advertised write cache: setting
	// fd_buffered_io=1 also sets attrib/emulate_write_cache=1, and the info
	// line reads "Mode: Buffered-WCE".
	//
	// The coupling is create-time only. MEASURED on Azure Linux 3.0, kernel
	// 6.6.144.1: emulate_write_cache can afterwards be forced back to 0 while
	// the file is still open without O_DSYNC -- buffering in volatile page
	// cache while telling the initiator there is no cache to flush. That
	// combination loses acknowledged writes on power loss and gives the
	// consumer no way to protect itself. The info line does NOT follow: it
	// stays "Buffered-WCE", because the kernel renders it from fbd_flags
	// alone and never consults the attribute (linux v6.6
	// drivers/target/target_core_file.c:963-966). That makes the info line
	// the authoritative reading of the backing mode, and reconcile uses it to
	// keep the attribute honest -- see applyCtx.constrainWriteCache.
	BufferedIO bool `json:"buffered_io,omitempty"`

	// Size is the device size in bytes. For fileio, if zero the size of
	// the existing backing file is used.
	Size int64 `json:"size,omitempty"`
	// WWN is the T10 vpd_unit_serial written to wwn/vpd_unit_serial — the
	// device's stable serial, NOT the initiator-visible NAA WWID (which the
	// kernel derives from it: 0x6001405<wwn> zero-padded, and is read-only).
	// If empty on create the kernel assigns one; discovery reports the
	// assigned value (stripping the "T10 ... :" read-back prefix). It is
	// preserved across save/restore so a volume keeps a stable identity
	// across reboots. When set it must be 16 lowercase hex digits (the
	// width that fits LIO's NAA designator).
	WWN string `json:"wwn,omitempty"`
	// VendorID, ProductID and Revision are the SCSI inquiry identity
	// strings (wwn/vendor_id, wwn/product_id, wwn/revision). Empty means
	// leave the kernel default. Like WWN they are immutable once the
	// backstore is exported (LUN-mapped), so they are set before mapping.
	VendorID  string `json:"vendor_id,omitempty"`
	ProductID string `json:"product_id,omitempty"`
	Revision  string `json:"revision,omitempty"`
	// Attributes are storage-object attrib/* values to enforce (e.g.
	// block_size). Only listed keys are managed. They are written after
	// enable but before the backstore is LUN-mapped (block_size is reset
	// to the device default if written before enable, and is immutable
	// once exported).
	Attributes map[string]string `json:"attributes,omitempty"`
}

// Portal is a TPG network portal (np/<ip>:<port>).
type Portal struct {
	// IP is the bind address. netip.Addr rather than a string so the address
	// is a value with one canonical form, not text with many: fd00::1,
	// fd00:0:0:0:0:0:0:1 and FD00::1 compare EQUAL here, where as strings
	// they did not and the kernel was handed the same endpoint twice.
	//
	// It also removes the family questions from every caller. Rendering
	// (including the brackets IPv6 needs) is netip.AddrPort's job, and
	// "is this a wildcard" is Addr.IsUnspecified() rather than a comparison
	// against two literals.
	IP netip.Addr `json:"ip"`
	// Port is this portal's TCP port. Per-portal, not shared: iSCSI defines a
	// portal as an endpoint, and RFC 3720 renders a TargetAddress as
	// <address>[:<port>],<portal-group-tag> -- the port belongs to the portal
	// while the TAG is what groups them. SendTargets reports "10.0.0.1:3260,1"
	// per portal and the kernel names each np/<ip>:<port> accordingly.
	//
	// Zero means DefaultPortalPort.
	//
	// uint16, matching what a TCP port IS. As an int it could hold a value no
	// port can take, and String and key narrowed it with an unchecked
	// conversion -- so Port: 68796 rendered as ":3260", not a visible error
	// but THE DEFAULT PORT, and the identity used by every create and prune
	// agreed with it. The type now makes that unrepresentable, which is the
	// same reasoning that moved IP to netip.Addr: the value has one canonical
	// form rather than many spellings.
	Port uint16 `json:"port,omitempty"`
}

// LUN is a TPG logical unit (lun/lun_<index>) mapping to a backstore.
type LUN struct {
	Index int `json:"index"`
	// Backstore is the name of the Backstore this LUN exposes.
	Backstore string `json:"backstore"`
}

// MappedLUN maps a TPG LUN into an ACL (acls/<iqn>/lun_<index>).
type MappedLUN struct {
	Index        int  `json:"index"`                   // mapped LUN number seen by the initiator
	TPGLUN       int  `json:"tpg_lun"`                 // the TPG LUN index it points at
	WriteProtect bool `json:"write_protect,omitempty"` // read-only export when true
}

// ACL is an initiator node ACL (acls/<initiator-iqn>).
type ACL struct {
	InitiatorIQN string      `json:"initiator_iqn"`
	MappedLUNs   []MappedLUN `json:"mapped_luns,omitempty"`
}

// TPG is an iSCSI target portal group (tpgt_<tag>).
type TPG struct {
	Tag     int      `json:"tag"`
	Enable  bool     `json:"enable"`
	Portals []Portal `json:"portals,omitempty"`
	LUNs    []LUN    `json:"luns,omitempty"`
	ACLs    []ACL    `json:"acls,omitempty"`
	// Attributes are attrib/* values to enforce (e.g. authentication,
	// generate_node_acls). Only listed keys are managed.
	Attributes map[string]string `json:"attributes,omitempty"`
}

// Target is an iSCSI target (iscsi/<iqn>).
type Target struct {
	IQN  string `json:"iqn"`
	TPGs []TPG  `json:"tpgs,omitempty"`
}

// Config is a complete desired-state description spanning backstores
// and iSCSI targets.
type Config struct {
	Backstores []Backstore `json:"backstores,omitempty"`
	Targets    []Target    `json:"targets,omitempty"`
}

func (p Portal) port() uint16 {
	if p.Port == 0 {
		return DefaultPortalPort
	}
	return p.Port
}

// dirName is the plugin_HBA directory for a backstore, e.g. "fileio_0".
func (b Backstore) dirName() string {
	return string(b.Type) + "_" + itoa(b.HBA)
}
