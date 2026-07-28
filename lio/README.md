# lio — Go library for the Linux LIO iSCSI target

A **stateless, declarative** Go library that manages the Linux kernel
LIO target directly through **configfs** (`/sys/kernel/config/target`),
replacing `targetcli`/`rtslib` for the operations we need. It owns no
persistent state and knows nothing about appliance concepts (volumes,
snapshots, databases, REST) — that separation is deliberate so this
package can later be split into its own repository unchanged.

## Package layout

```
lio/
  configfs/      pure filesystem layer over configfs (no LIO logic)
  model.go       kernel object types: Backstore, Target, TPG, Portal, LUN, ACL, MappedLUN
  paths.go       object → configfs path mapping
  backstore.go   core backstore apply/discover (fileio, iblock)
  iscsi.go       target/TPG/portal/LUN/ACL apply, discover, ordered teardown
  validate.go    structural + naming + dependency validation
  errors.go      categorised error model (Kind)
  config.go      Manager: Apply / Remove / Discover
```

## Model → configfs

| object     | configfs path                                            |
|------------|----------------------------------------------------------|
| Backstore  | `core/<plugin>_<hba>/<name>`                             |
| Target     | `iscsi/<iqn>`                                            |
| TPG        | `iscsi/<iqn>/tpgt_<tag>`                                 |
| Portal     | `.../tpgt_<tag>/np/<ip>:<port>`                          |
| LUN        | `.../tpgt_<tag>/lun/lun_<n>` → symlink to the backstore  |
| ACL        | `.../tpgt_<tag>/acls/<initiator-iqn>`                    |
| MappedLUN  | `.../acls/<iqn>/lun_<n>` → symlink to the TPG LUN        |

## Usage

```go
m := lio.New(configfs.Default())

cfg := lio.Config{
    Backstores: []lio.Backstore{{Type: lio.FileIO, HBA: 0, Name: "test0",
        Dev: "/var/lib/glitr/test0.img"}},
    Targets: []lio.Target{{IQN: "iqn.2026-01.dev.glitr:target", TPGs: []lio.TPG{{
        Tag: 1, Enable: true,
        Portals: []lio.Portal{{IP: "10.10.0.1", Port: 3260}},
        LUNs:    []lio.LUN{{Index: 0, Backstore: "test0"}},
        ACLs:    []lio.ACL{{InitiatorIQN: "iqn.2026-01.dev.glitr:initiator",
            MappedLUNs: []lio.MappedLUN{{Index: 0, TPGLUN: 0}}}},
    }}}},
}

rep, err := m.Apply(cfg)   // create/update in dependency order, idempotent
cur, err := m.Discover()   // reconstruct live state
_,   err  = m.Remove(cfg)  // reverse-order teardown
```

Guarantees: **create order** is backstore → target → TPG → portal → LUN
→ ACL(+mapped LUN); **delete** is the reverse. `Apply` is idempotent
(a satisfied config produces zero changes); compatible objects are left
untouched; immutable differences are reported as `KindIncompatible`.

The library does **not** create backing files/devices — the caller
provides an existing path (an appliance responsibility).

## Error model

Errors are `*lio.Error` with a `Kind`: `not-found`, `invalid-spec`,
`kernel-rejected`, `dependency`, `busy`, `incompatible`, `configfs`.
Use `lio.KindOf(err)` to branch programmatically.

## Testing

- **Unit** (host, no root): `go test ./lio/...` — configfs primitives,
  validation, and discovery against a synthetic configfs tree.
- **Integration** (live kernel, root): `tools/livetest.sh` builds the
  test static, ships it to the `target` VM and runs `TestLive`
  (create → discover → idempotent re-apply → attribute update → remove).
- **Live suites** (real kernel, real initiators): `tools/labtest.sh <suite>`
  — eleven of them, 250 assertions. See `docs/VERIFICATION.md`.

The Tier 2 success criterion — rebuild the Tier 1 manual export entirely
from the library, with no targetcli — was met and is recorded in
`tier2/baseline-config.json`, the config it was driven from. The script
that drove it is gone: it ran `lioctl apply`, and step 1 tore down a
targetcli-built target. `targetcli` is not packaged on Azure Linux 3,
which the lab target now runs, so it had been unrunnable for some time.

## Driving the library from a shell

`cmd/lish` — `lish apply|discover|validate|clear` take Config JSON on
stdin/stdout for scripting, and `lish` with no verb is an interactive
shell over the live tree. It supersedes the former `lioctl`, which was
deleted once the two had the same surface (`lish apply` is `Sync`).
