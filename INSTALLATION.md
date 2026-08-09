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
curl -s 127.0.0.1:8080/health           # -> {"status":"ok"}
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
response too.

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

`POST /volumes/{uuid}/lununmap` for a host that holds a SCSI-3 reservation
causes the kernel to release it — initiators that reservation was fencing can
write immediately, and re-attaching does not restore it. The response carries a
`warning` field saying so, and the daemon logs it.

This is not refused, because an operator must be able to detach a host that may
itself be dead. If the volume is still in use by a cluster, re-establish
fencing before allowing writes.

## 5. Create and export a volume (REST API)

The REST API listens on `127.0.0.1:8080` by default. **It is unauthenticated —
keep it on a trusted interface** (change with `applianced serve -listen`).

| Method & path | Purpose |
|---|---|
| `GET /health` | liveness **and fencing state** — see below |
| `GET /target` | target IQN + summary |
| `POST /volumes` | create a volume — body `{"size": <bytes>}` |
| `GET /volumes`, `GET /volumes/{uuid}` | list / get |
| `DELETE /volumes/{uuid}` | delete |
| `POST /volumes/{uuid}/resize` | grow a volume |
| `POST /volumes/{uuid}/snapshot` | reflink snapshot (needs XFS data disk) |
| `POST /volumes/{uuid}/lunmap` | export — body `{"host":"<uuid>","lun":<n>}` |
| `POST /volumes/{uuid}/lununmap` | unexport — **may release a reservation**, see below |
| `POST /hosts` | register an initiator — body `{"iqns":["<iqn>", ...]}` |
| `GET /hosts`, `DELETE /hosts/{uuid}` | list / delete |

Example — register an initiator, create a 1 GiB volume, and map it at LUN 1:

```sh
# 1. register the initiator by its IQN (find it in the initiator's
#    /etc/iscsi/initiatorname.iscsi on Debian, or /etc/iscsi/initiatorname.iscsi
#    for iscsi-initiator-utils):
curl -s -XPOST 127.0.0.1:8080/hosts   -d '{"iqns":["iqn.1993-08.org.debian:01:example"]}'
# 2. create a 1 GiB volume:
curl -s -XPOST 127.0.0.1:8080/volumes -d '{"size":1073741824}'
# 3. map volume -> host at LUN 1 (use the uuids returned above):
curl -s -XPOST 127.0.0.1:8080/volumes/<VOL_UUID>/lunmap -d '{"host":"<HOST_UUID>","lun":1}'
```

> **Azure Linux minimal-os has no `curl`.** Either `tdnf install -y curl`, or
> drive the API with python3 (present by default):
>
> ```python
> import json, urllib.request
> def post(path, obj):
>     r = urllib.request.urlopen("http://127.0.0.1:8080" + path,
>                                data=json.dumps(obj).encode(), timeout=10)
>     return json.load(r)
> h = post("/hosts",   {"iqns": ["iqn.1993-08.org.debian:01:example"]})
> v = post("/volumes", {"size": 1073741824})
> m = post("/volumes/%s/lunmap" % v["uuid"], {"host": h["uuid"], "lun": 1})
> print(h["uuid"], v["uuid"], m["wwid"])
> ```

## 6. Connect an initiator

On the client host, make its `InitiatorName` match the IQN you registered, then:

```sh
# Debian: sudo apt-get install -y open-iscsi
# Azure Linux: sudo tdnf install -y iscsi-initiator-utils
sudo iscsiadm -m discovery -t st -p <APPLIANCE_IP>
sudo iscsiadm -m node -T iqn.2026-01.dev.glitr:appliance -p <APPLIANCE_IP> --login
lsblk    # the mapped volume appears as /dev/sdX with the volume's wwid
```

`iqn.2026-01.dev.glitr:appliance` is the default target IQN (change with
`applianced serve -iqn`).

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
