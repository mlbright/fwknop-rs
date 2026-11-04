# fwknop-rs translates fwknop-go and adds nothing it lacks

fwknop-rs is a translation of fwknop-go (branch `mlbright/main`), not a port of C fwknop. Where Go deliberately does less than C, so do we:

- An access message carries one access spec. C accepts `tcp/22,udp/53`; Go rejects it, and so do we.
- No GPG encryption, packet capture (pcap) mode, NAT forwarding by the server itself (NAT access is only passed to actions as a placeholder), or replay cache saved to disk.
- Linux and macOS only. Go's `fwknopd` never built on Windows (it uses `log/syslog`), and we do not support Windows for any crate.

The goal is a drop-in replacement whose behaviour can be checked against the Go binaries. Each of these could be added later as its own decision, but none should be added just because C has it. We do fix clear bugs in the Go code, and every behaviour that differs from Go is listed in the deviations document.
