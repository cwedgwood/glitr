# Security Policy

## Reporting a Vulnerability

Please use GitHub's private vulnerability reporting for this repository:

1. Open the **Security** tab.
2. Select **Report a vulnerability**.
3. Include the affected version, a clear description, reproduction steps, and
   the potential impact.

Do not disclose suspected vulnerabilities in a public issue or pull request.

Reports are acknowledged as soon as practical. Please allow time for
investigation, mitigation, and coordinated disclosure before publishing
details.

## Scope, and what to expect

This project is published as working code rather than as a maintained service.
Fixes are best-effort and there is no support commitment, so please weigh that
before depending on it where a timely security response matters.

Two things are worth knowing before reporting, because they are documented
properties rather than defects:

- **The REST API in `appliance` is unauthenticated.** It is meant to be bound
  to a trusted interface. A report that the API can be driven by anyone who can
  reach it is describing the design; a report that it can be reached from
  somewhere it should not be, or that binding it to loopback does not confine
  it, is a defect.
- **`setup-system` requires root and modifies the host** — kernel modules,
  mounts, `/etc/fstab`, a systemd unit. That is its purpose. A report that it
  changes the system is expected; a report that it changes something it was not
  asked to, or that an input to it can be used to do so, is a defect.

Reports that are especially welcome, because they undermine what this exists
for: anything that lets a fenced initiator write to a volume, or that makes the
software report a reservation state the device does not actually hold. The rule
throughout is that it may over-fence but must never under-fence, so a case
where it under-fences is the most serious class of bug here.
