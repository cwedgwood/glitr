# glitr

Go libraries for driving the Linux kernel's LIO iSCSI target through configfs,
with a working storage appliance built on them as the demonstration.

The libraries are the point. `applianced` exists to show they are sufficient
for something real, and to be the thing that gets exercised against an actual
kernel — a library whose only exercise is its own unit tests has not been
shown to work.

## Why

LIO is configured by writing files under `/sys/kernel/config/target`, and the
tree is a pile of directories, attributes and symlinks with ordering rules that
are not written down anywhere. Building a target means performing a sequence of
mutations in the right order; changing one means working out which of them to
undo.

This library does not do that. You describe the target you want as a value, and
it converges the kernel onto it.

```go
m := lio.New(configfs.Default())

rep, err := m.Sync(lio.Config{
	Backstores: []lio.Backstore{{
		Type: lio.FileIO, Name: "vol0", Dev: "/var/lib/glitr/vol0.img",
		Size: 1 << 30, WWN: "bc0c3252de2b4c91",
	}},
	Targets: []lio.Target{{
		IQN: "iqn.2026-01.example:t",
		TPGs: []lio.TPG{{
			Tag: 1, Enable: true,
			Portals: []lio.Portal{{IP: netip.MustParseAddr("::"), Port: 3260}},
			LUNs:    []lio.LUN{{Index: 0, Backstore: "vol0"}},
			ACLs: []lio.ACL{{
				InitiatorIQN: "iqn.1993-08.org.debian:01:a",
				MappedLUNs:   []lio.MappedLUN{{Index: 0, TPGLUN: 0}},
			}},
		}},
	}},
})
```

`Sync` is idempotent, reports what it changed, and is safe to call against a
tree it did not create. `Discover` reads the live tree back into the same
shape, so save and restore is a round trip rather than a translation.

That shape is the point. A configuration is a value you can build, compare,
serialise, diff and hand to a reconciler, so the program holding it decides
what the target looks like and the kernel is made to agree — rather than the
program issuing changes and inferring the result afterwards. Values are kept in
one canonical form for the same reason: an address is a `netip.Addr` and a port
is a `uint16`, so `10.0.0.1` has exactly one spelling and a port that cannot
exist cannot be written down.

## What it is actually for

SCSI-3 persistent reservations. Everything else is in service of being able to
fence a node off a volume and *know* it is fenced.

The rule throughout is that the system may over-fence but must never
under-fence: wherever those two conflict, availability loses.

It is why `applianced` refuses to start when the reservation state it saved
cannot be read or is damaged, rather than serving volumes a previously-fenced
initiator could write to. Where a saved reservation is readable but does not
take effect — an initiator whose ACL is gone, say — it does start, because
refusing would take down every other volume on the target, and reports the
condition on `/health` as `pr_unbound` with a top-level status of `warning`.
That distinction is worth knowing before you rely on it: **the daemon starting
is not by itself a statement that every saved fence is in effect.** `/health`
is.

It is also why verdicts in that area are SCSI status bytes and errnos rather
than the text some tool printed — `0x18` means the same thing in every locale,
and `strerror` does not.

Volumes are thin: the backing file is sparse, and they advertise `UNMAP` so a
guest can return space it has freed. The appliance can therefore be
overcommitted — deliberately, since the alternative is pretending a sparse file
is a full one — so the data disk's free space is the number that matters, not
the sum of the volume sizes.

## Layers

Each is usable without the ones after it.

| package | what it is |
|---|---|
| `lio/configfs` | the filesystem primitives — typed reads and writes, with `Rmdir` and `Unlink` kept distinct because destroying a kernel object and unmapping a link are different operations that `os.Remove` conflates |
| `lio` | the LIO object model and a stateless declarative engine: `Sync`, `Discover`, `Diff`/`ApplyDelta`, plus SCSI-3 PR state, APTPL persistence and drift reporting |
| `scsi` | `SG_IO` and PERSISTENT RESERVE IN/OUT — reservations as structured data rather than parsed `sg_persist` output |
| `hostlock` | the host-wide single-writer interlock, because configfs has no serialisation of its own |
| `saveconfig` | the discovered configuration as JSON, so it survives a reboot |
| `storage` | bytes: sparse files, reflink (`FICLONE`) copies, addressed by an identifier the caller mints |
| `appliance` | the demonstration: named volumes, snapshots and hosts, LUN mapping, and a REST control plane over everything above |

`cmd/applianced` is the daemon and `cmd/lish` an interactive shell over `lio`.
Both are example programs. `storage` and `appliance` are one answer rather than
the answer — replace `storage` with a real array or an LVM pool and the layers
below neither know nor care.

The appliance exists to absorb the gap between what external code expects of an
array and what SCSI and LIO actually provide. Things have names you choose;
volumes and snapshots are separate kinds in separate namespaces; a repeated
create returns what is already there. None of that exists in LIO, which has
WWNs, initiator IQNs, ACLs and LUN indexes. A typed Go client for the REST API
is `applianceclient`.

Installing the appliance: [`INSTALLATION.md`](INSTALLATION.md).

## Requirements

Go 1.25 or newer, and Linux with configfs and the LIO modules
(`target_core_mod`, `iscsi_target_mod`). Reflink snapshots need a filesystem
that supports `FICLONE`, such as XFS or Btrfs.

## State, honestly

The code is working and has been exercised against a real kernel — fourteen
live suites and 303 assertions, on an Azure Linux 3.0 target with two Debian
initiators driving genuine iSCSI sessions, including reservation conflicts,
multipath failover, fencing across a reboot, and breaking a reservation
deliberately and proving the previously-fenced node can then write.

**That harness is not in this repository yet.** What ships here is the code it
tested, plus unit and fuzz tests you can run anywhere with `go test ./...`. The
live suites, and CI to run them, are intended to follow.

Also worth knowing before you deploy it:

- The REST API is **unauthenticated**. Bind it to a trusted interface. That is
  a deliberate non-goal rather than an oversight — the appliance is a
  demonstration, and authentication is policy that belongs to whatever fronts
  it. It is not expected to hold forever.
- Parsers are fuzzed because their input comes from the kernel, and the
  kernel's *prose* is not a stable interface even though its ABI is. They are
  built to degrade to "I cannot tell" rather than to guess.

## Conventions

These are the habits the code was written under, offered in case they are
useful to anyone extending it.

- Behaviour settled by reading kernel source is cited in the code as version,
  file and line, so it can be re-checked against a later kernel.
- Verdicts rest on numbers — SCSI status, errno, ioctl flags — never on parsing
  a tool's prose, which changes with version and locale.
- A new assertion is negative-controlled: break the thing, confirm the test
  fails, restore it. A test that has never failed has not been shown to test
  anything.
- Absent is not the same as unreadable. A failed read is never reported as a
  known-good value, and an empty answer is never reported as an authoritative
  one.

## Licence

Apache-2.0. See [`LICENSE`](LICENSE). It includes an explicit patent grant,
which felt worth having for code implementing SCSI persistent reservations.
