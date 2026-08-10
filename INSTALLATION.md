# Installing the glitr storage appliance

> **Status: draft.** This guide is aimed at people (and agents) reading it on
> GitHub who want to stand up a working iSCSI storage appliance from scratch on
> **Debian 13** or **Azure Linux 3.0**, including building a test VM.

## What you are installing

`applianced` is a small Go daemon that turns a Linux host into an **iSCSI
storage appliance**. It manages the in-kernel **LIO** iSCSI target directly
through `configfs`, exposing a REST API to create *volumes*
(files on a data disk), register *hosts* (iSCSI initiators by IQN), and *map*
volumes to hosts as LUNs. Initiators then log in with `iscsiadm` and see
ordinary block devices.

The reusable pieces are Go libraries (`lio`, `storage`); `applianced` is the
control plane built on top. Everything below drives `applianced`.

## Requirements

- x86_64 Linux host running **Debian 13 (trixie)** or **Azure Linux 3.0**.
  Both ship the LIO target modules in their stock kernel.
- **root** on that host (for `modprobe`, `configfs`, `mkfs`, `systemctl`).
- A **dedicated data disk** (e.g. `/dev/vdb`) for volume storage. Format it
  **XFS** (done for you by `setup-system`) — XFS reflink gives copy-on-write
  snapshots. Without a dedicated reflink-capable disk the appliance still
  serves volumes, but snapshots are disabled.
- A **second host or VM** to act as the iSCSI initiator for testing
  (`open-iscsi` on Debian, `iscsi-initiator-utils` on Azure Linux).
- To build `applianced`: a **Go toolchain** (see `go.mod` for the version).

## 1. Build `applianced`

Build a static binary (runs on any x86_64 Linux, so you can build once and copy
it to the target host):

```sh
git clone https://github.com/cwedgwood/glitr
cd glitr
CGO_ENABLED=0 go build -o applianced ./cmd/applianced

# install on the appliance host:
sudo install -m0755 applianced /usr/local/sbin/applianced
```

## 2. Preflight — check host readiness (read-only)

```sh
sudo applianced preflight
```

This makes **no changes**. It reports `OK` / `WARN` / `FATAL` for: running as
root, distro detection, LIO kernel modules, `configfs`, the iSCSI fabric,
conflicting `targetcli` units, whether the data root is XFS, and whether the
ports are free. A fresh host is normally **`READY` with warnings** (the iSCSI
fabric isn't created yet and the data root isn't XFS until you run
`setup-system`). Fix any `FATAL` items before continuing.

## 3. `setup-system` — prepare the host (idempotent)

Point it at your blank data disk and let it format, mount, install the service,
and start it:

```sh
sudo applianced setup-system -data-disk /dev/vdb -start
```

What it does (all idempotent, safe to re-run):

- loads the LIO modules and persists them via `/etc/modules-load.d`,
- mounts `configfs` and creates `/var/target` + the iSCSI fabric group,
- masks conflicting `targetcli` units (a no-op where they aren't installed),
- installs `mkfs.xfs` if missing (`apt-get` on Debian, `tdnf` on Azure Linux),
- formats the data disk **XFS**, mounts it at the storage root, and adds an
  `/etc/fstab` entry,
- installs the systemd unit (`/etc/systemd/system/applianced.service`),
- with `-start`, runs `systemctl enable --now applianced`.

Flags: `-data-disk <dev>` (optional — omit to prep without a dedicated disk, in
which case **snapshots are disabled** because the storage root lands on a
non-reflink filesystem), `-root <path>` (storage root, default `/var/lib/glitr`),
`-force` (allow `mkfs` over an existing filesystem), `-start` (enable + start).
If you omit `-start`, start it yourself: `sudo systemctl enable --now applianced`.

## 4. Verify it's serving

```sh
sudo applianced preflight -runtime      # probes the running daemon instead of ports
curl -s 127.0.0.1:8080/v1/health        # -> {"status":"ok"}
sudo applianced inspect                 # dumps the live LIO configuration
```

`preflight -runtime` should print `RESULT: READY.` with `appliance-health` OK.

### `/health` is not just liveness

Three verdicts, and the middle one is the reason to read the body rather than
only the status code:

| `status` | HTTP | meaning |
| --- | --- | --- |
| `ok` | 200 | serving, nothing outstanding |
| `warning` | 200 | serving, but **a reservation somebody relies on is not in effect** (`pr_unbound`) or its holder cannot release it (`pr_stranded`) |
| `degraded` | 503 | the kernel tree and the database disagree; see `error` |

`warning` is deliberately still 200: the appliance is alive and serving, and a
liveness probe that restarted it would interrupt the volumes that are fine
without restoring the reservation that is not. **Alert on the `status` field,
not only on the status code.** The fencing fields are present on the degraded
response too — so **decode the body on a 503**, rather than treating the status
as an error and discarding it. That is the one response where `pr_unbound` and
`error` matter most, and it is the one a client is most likely to throw away.

### Volumes are thin, and space comes back

A volume's backing file is sparse: a 1 TiB volume costs nothing until something
writes to it, and the appliance will happily hand out more capacity than the
data disk has. **That is overcommit, and running out is your problem to
watch** — `df` on the data disk tells you the truth, not the volume sizes.

Volumes advertise `UNMAP`, so a guest that discards (`fstrim`, `mount -o
discard`, `blkdiscard`) returns the space to the data disk. Two things are
worth knowing:

- **A snapshot shares its parent's blocks.** Discarding a range on one of them
  frees nothing until *every* volume sharing those blocks has discarded it.
  Trimming a clone and seeing `df` not move is correct behaviour, not a leak.
- **Reads of a discarded region return zeros**, but the device does not
  formally promise it (`LBPRZ` is not advertised), so do not rely on discard as
  a way to erase data.

`-no-unmap` turns this off, for a backing filesystem that cannot punch holes.
Volumes are still sparse; they just never shrink.

### Unmapping a reservation holder releases its reservation

`DELETE /v1/volumes/{name}/connections/{host}` for a host that holds a SCSI-3 reservation
causes the kernel to release it — initiators that reservation was fencing can
write immediately, and re-attaching does not restore it. The response carries a
`warning` field saying so, and the daemon logs it.

This is not refused, because an operator must be able to detach a host that may
itself be dead. If the volume is still in use by a cluster, re-establish
fencing before allowing writes.

`PUT`/`PATCH /v1/hosts/{name}/iqns` can do the same thing by a different route: an IQN
that is removed loses its ACL, which is the same kernel path, so removing the
IQN of a reservation holder releases the reservation. It carries the same
`warning` field, on both the success and the failure response. Adding IQNs
cannot release anything and never warns.

## 5. Create and export a volume (REST API)

The REST API listens on `127.0.0.1:8080` by default. **It is unauthenticated —
keep it on a trusted interface** (change with `applianced serve -listen`).

Every path is served under `/v1`. Unversioned paths are not served; they answer
404 with a pointer, so an old client fails loudly rather than mysteriously.

| Method & path | Purpose |
|---|---|
| `GET /v1/health` | liveness **and fencing state** — see below |
| `GET /v1/target` | target IQN + portals — what an initiator needs, asked once rather than repeated on every connection |
| `PUT /v1/target/portals` | replace the portal set |
| `POST /v1/volumes` | create — body `{"name":"...","size":<bytes>}` |
| `GET /v1/volumes`, `GET /v1/volumes/{name}` | list / get (a uuid works wherever a name does) |
| `PATCH /v1/volumes/{name}` | rename — body `{"name":"..."}` |
| `DELETE /v1/volumes/{name}` | delete |
| `POST /v1/volumes/{name}/resize` | grow |
| `POST /v1/snapshots` | snapshot — body `{"name":"...","source":"<volume>"}` |
| `GET /v1/snapshots`, `GET /v1/snapshots/{name}` | list / get |
| `POST /v1/{volumes\|snapshots}/{name}/connections` | export — body `{"host":"...","lun":<n>}` |
| `DELETE /v1/{volumes\|snapshots}/{name}/connections/{host}` | unexport — **may release a reservation** |
| `GET /v1/connections` | list — filter with `?object=`, `?object_kind=`, `?host=` |
| `POST /v1/hosts` | register — body `{"name":"...","iqns":["<iqn>", ...]}`, iqns may be empty |
| `GET /v1/hosts`, `GET /v1/hosts/{name}` | list / get |
| `PATCH /v1/hosts/{name}` | rename |
| `PUT /v1/hosts/{name}/iqns` | replace the binding set |
| `PATCH /v1/hosts/{name}/iqns` | add/remove bindings — body `{"add":[...],"remove":[...]}` |
| `DELETE /v1/hosts/{name}` | delete |

### Warnings ride on failures too

`PUT`/`PATCH /v1/hosts/{name}/iqns` and `DELETE …/connections/{host}` can
return a `warning` saying a SCSI-3 reservation was released — that fencing is
**gone**, and re-attaching does not restore it.

It is present on the **failure** response as well as the success one, and that
is the case to handle. These operations commit before they reconcile, so the
change can be durable when the error happens: the fence is already lost and the
call still returned an error. **Retrying will not tell you again** — a repeated
disconnect takes the idempotent path, succeeds, and says nothing. Read
`warning` on every response, whatever the status.

### The model

Things have **names you choose**. A name is unique within its kind, and you
address everything by it; the appliance's own UUID keeps working wherever a
name does, so nothing breaks if you stored one.

**Names are yours, and they are reusable.** Deleting an object frees its name;
creating another with that name makes a *different* object with a different
uuid and a different WWN. A name identifies what holds it now, never what held
it before — so if you need to refer to something across a delete, keep its
uuid.

**Provenance can outlive its subject.** A snapshot records the `source` it was
made from, as a **uuid**, and you may delete that source: the snapshot's bytes
are its own (it is a reflink copy, not a reference), so nothing about it stops
working. `source` then names something that no longer resolves, which is the
honest answer — recording the source's *name* instead would let a later,
unrelated object with that name appear to be the origin. The same applies to a
clone whose snapshot has been deleted. Two consequences worth planning for:

- **Repeat a create with the source's uuid, not its name.** Replaying with the
  uuid keeps working after the source is gone. Replaying with the name cannot
  be matched — the appliance will not guess — and is refused with
  `configuration_mismatch`.
- **Deleting a source frees little space.** A snapshot shares its parent's
  blocks until one of them is written, so the capacity stays accounted for
  until every object sharing those blocks is gone.

**Volumes and snapshots are separate kinds in separate namespaces.** A volume
and a snapshot may both be called `db-1` — they are different things, and
asking for one never returns the other. Where a path does not say which kind it
means, neither do we: `GET /v1/connections?object=db-1` is **refused** while
that name is held by both, and `&object_kind=volume` resolves it. A uuid is
never ambiguous. A *clone* is a volume created from a
snapshot (`{"name":"...","source":"<snapshot>","source_kind":"snapshot"}`),
which is a distinction the appliance can state rather than leave you to infer.

**Renaming is safe while mounted.** An initiator identifies a device by its
WWN, which is derived from the UUID and never moves.

**Repeating a create is safe, and you can tell.** The same name with the same
shape returns what is already there rather than making a second object; a
different shape is refused with `configuration_mismatch`. **`201` means this
call made it, `200` means it was already there** — for volumes, snapshots,
hosts and exports alike, so a controller that cannot tell whether its first
attempt landed can replay it and still distinguish an adoption from a creation.
Capacity is deliberately not compared on a repeat, because an object can be
resized after it is made; compare it yourself if a difference means something
to you. Sizes are at least 1MiB, and a whole
number of the backing store's granularity — 4096 bytes on the file-backed
store, which is the only one today. The error names both numbers, so a caller
does not have to know them in advance.

**You choose the LUN.** The appliance never assigns one — in a cluster the same
volume usually has to appear at the same LUN on every node, and a number picked
per connection cannot promise that. Omitting it is an error, not a guess.

Example — register an initiator, create a 1 GiB volume, and map it at LUN 1:

```sh
# 1. register the initiator by its IQN (find it in the initiator's
#    /etc/iscsi/initiatorname.iscsi on Debian, or /etc/iscsi/initiatorname.iscsi
#    for iscsi-initiator-utils):
curl -s -XPOST 127.0.0.1:8080/v1/hosts   -d '{"name":"node-7","iqns":["iqn.1993-08.org.debian:01:example"]}'
# 2. create a 1 GiB volume:
curl -s -XPOST 127.0.0.1:8080/v1/volumes -d '{"name":"db-1","size":1073741824}'
# 3. map volume -> host at LUN 1, by the names given above:
curl -s -XPOST 127.0.0.1:8080/v1/volumes/db-1/connections -d '{"host":"node-7","lun":1}'
```

> **Azure Linux minimal-os has no `curl`.** Either `tdnf install -y curl`, or
> drive the API with python3 (present by default):
>
> ```python
> import json, urllib.request
> def post(path, obj):
>     r = urllib.request.urlopen("http://127.0.0.1:8080/v1" + path,
>                                data=json.dumps(obj).encode(), timeout=10)
>     return json.load(r)
> h = post("/hosts",   {"name": "node-7", "iqns": ["iqn.1993-08.org.debian:01:example"]})
> v = post("/volumes", {"name": "db-1", "size": 1073741824})
> m = post("/volumes/db-1/connections", {"host": "node-7", "lun": 1})
> print(h["name"], v["name"], m["wwid"])
> ```

## 6. Connect an initiator

On the client host, make its `InitiatorName` match the IQN you registered, then:

```sh
# Debian: sudo apt-get install -y open-iscsi
# Azure Linux: sudo tdnf install -y iscsi-initiator-utils
# Ask the appliance what it is called; do not assume a name.
IQN=$(curl -s <APPLIANCE_IP>:8080/v1/target | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_iqn"])')

sudo iscsiadm -m discovery -t st -p <APPLIANCE_IP>
sudo iscsiadm -m node -T "$IQN" -p <APPLIANCE_IP> --login
lsblk    # the mapped volume appears as /dev/sdX with the volume's wwid
```

Discovery reports the name too, so `iscsiadm -m discovery` alone is enough if
you would rather read it off the output. **There is no fixed target IQN to
hardcode** — see below.

## The appliance's name, and cloning one

**One appliance is one target with one IQN.** Two targets means two appliances:
two machines, each with its own identity, portals and volumes, sharing nothing.

**The name is generated, once, and then recorded.** On its first start the
appliance derives `iqn.2026-01.dev.glitr:<machine-id>` from `/etc/machine-id`
and writes it into its database. There is deliberately no shared default:
two appliances installed from the same image and unit file would otherwise both
answer to one name, and an initiator offered two targets with the same IQN does
not report a conflict — it treats them as one.

Pass `applianced serve -iqn <name>` to choose your own. It is honoured on the
**first** start only. After that the record wins and the flag is reported as
ignored (`iqn_flag_ignored` on `/health`), because renaming a live target
destroys it: the reconciler removes the one the kernel has and builds another,
taking every session and every persistent reservation with it.

An appliance upgraded from a build that predates this keeps the name it is
already serving, rather than being renamed out from under its initiators.

### Cloning the VM

Copying an appliance copies its identity — and its volumes' WWNs, which is the
more dangerous half: an initiator identifies a *device* by its WWN, and
multipath gathers same-WWN devices into one path set rather than reporting a
conflict.

So a copied appliance **refuses to start**. It notices that the machine ID
recorded in its database is not this machine's, says so, and stops. Resolve it
deliberately:

```sh
sudo systemctl stop applianced
# keep the volumes; every one gets a NEW wwn so this appliance cannot
# collide with the one it was copied from:
sudo applianced reinit -root /var/lib/glitr -adopt
# ...or start empty, setting the existing volumes aside rather than deleting:
sudo applianced reinit -root /var/lib/glitr -wipe
sudo systemctl start applianced
```

Neither is the default: the two answers are opposites and both concern
somebody's data. Both take a new identity (add `-iqn` to choose it rather than
derive it) and clear the recorded portals, since those describe the machine and
a clone is on different hardware.

This depends on the clone having a different `/etc/machine-id`. Preparing an
image the usual way — truncating that file so systemd regenerates it at first
boot — is what makes each copy detectable. A host with no machine ID at all
still works, but cannot have its clones detected and must be given `-iqn`.

## 7. Reboot persistence

After `setup-system`, everything survives a reboot with **no manual steps**:
`modules-load.d` reloads the LIO modules, `fstab` remounts the data disk, the
systemd unit auto-starts `applianced`, and `applianced` recreates the (volatile,
cleared-every-boot) `configfs` iSCSI fabric and **replays all volumes and
exports from its on-disk database**. Verified on both Debian and Azure Linux.

> The service is intentionally **not** ordered after `network-online.target`:
> the daemon binds wildcard addresses (`0.0.0.0:3260` + the REST listener), so it
> must not be held hostage to a NIC that never comes online.

## Distro differences

| | Debian 13 | Azure Linux 3.0 |
|---|---|---|
| package manager | `apt-get` | `tdnf` |
| LIO target modules | stock kernel (`linux-image-*`) | stock `kernel` package |
| `mkfs.xfs` package | `xfsprogs` | `xfsprogs` |
| iSCSI initiator package | `open-iscsi` | `iscsi-initiator-utils` |
| `targetcli` present? | yes — `setup-system` masks its units | not packaged (nothing to mask) |
| `curl` preinstalled? | yes | **no** on minimal-os (use python3 / `tdnf install curl`) |
| `configfs` auto-mounts? | yes | yes |

`setup-system` handles these differences automatically; the table is for your
awareness when driving the box by hand.

## Building a test VM

You need a Linux VM (or bare-metal host) per the Requirements above, with a
second disk for volume storage. Nothing here is fussy about how you make one:
any image that boots, takes an ssh key and can be given a spare virtio disk
will do.

Two notes that cost real time if you meet them cold:

- **Debian** — use the **genericcloud** qcow2 with cloud-init to inject a user
  and ssh key, and attach the second virtio disk as the data disk.

- **Azure Linux 3.0** — it publishes **no** directly-bootable cloud image. What
  is on MCR (`azurelinux/3.0/image/minimal-os`) is an OCI-wrapped bare
  `image.vhdx` that is the *input to the Azure Linux Image Customizer*, not a
  runnable VM: no ssh, no cloud-init, no login, and a ~490 MB root that fills
  up if you install much into it. Run the official `imagecustomizer` container
  over it to bake in ssh, a login, `console=ttyS0`, DHCP and a grown root, then
  boot the result with OVMF UEFI + virtio. Regenerating the initramfs there is
  host-only by default, so include the virtio drivers or it will not find its
  own root disk.

## Troubleshooting

- **`preflight` warns "data-fs … is not XFS" / snapshots don't work** — you ran
  `setup-system` without `-data-disk`, so the storage root is on a non-reflink
  filesystem. Re-run with `-data-disk <blank-dev>`.
- **`applianced` won't start after reboot** — check `systemctl status applianced`
  and `journalctl -u applianced -b`. The unit is deliberately not tied to
  `network-online.target`; if you re-add that dependency, a NIC that never comes
  online will hang startup.
- **(qemu `-netdev socket` labs) initiator can't reach the target after the
  target reboots** — the socket L2 link drops (ARP goes `INCOMPLETE`); bounce the
  *initiator* VM to reconnect it. This is a lab artifact, not the appliance.
- **ssh "Connection timed out during banner exchange" into a qemu user-net VM** —
  `sshd` is hanging on reverse DNS of the SLiRP client; set `UseDNS no` in
  `sshd_config`.
