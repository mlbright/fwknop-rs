# systemd integration for fwknopd

This directory contains the systemd service unit for running `fwknopd`, the
fwknop-rs SPA server daemon, as a supervised system service.

| File              | Purpose                                  |
|-------------------|------------------------------------------|
| `fwknopd.service` | systemd service unit (`Type=simple`)     |

## Install

From the repository root:

```bash
sudo make install-systemd
```

This installs the `fwknopd` binary to `/usr/local/bin`, copies the unit to
`/etc/systemd/system/fwknopd.service`, and drops sample configuration into
`/etc/fwknop/` (as `*.sample` files — existing configs are never overwritten).

See the [main README](../README.md#running-fwknopd-under-systemd) for the full
configure-and-enable walkthrough.

## Uninstall

```bash
sudo make uninstall-systemd
```

## Notes

- The unit runs `fwknopd --foreground` so systemd supervises the process
  directly; no PID file is used.
- `fwknopd` manages the host firewall, so the unit grants `CAP_NET_ADMIN` /
  `CAP_NET_RAW`. If your firewall action commands fail to apply, relax the
  hardening directives near the bottom of `fwknopd.service`.
- The default `ExecStart` path is `/usr/local/bin/fwknopd`. If you install the
  binary elsewhere (e.g. via a different `PREFIX`), edit `ExecStart` to match.
