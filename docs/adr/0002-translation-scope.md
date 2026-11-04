# fwknop-rs translates fwknop-go and adds nothing it lacks

fwknop-rs is a translation of fwknop-go (branch `mlbright/main`), not a port of C fwknop. Where Go deliberately does less than C, so do we:

- An access message carries one access spec. C accepts `tcp/22,udp/53`; Go rejects it, and so do we.
- No GPG encryption, packet capture (pcap) mode, NAT forwarding by the server itself (NAT access is only passed to actions as a placeholder), or replay cache saved to disk.
- Linux only. Go's `fwknopd` never built on Windows (it uses `log/syslog`), and, unlike fwknop-go, fwknop-rs does not support macOS or the BSDs either, so there is one platform to test. The pf, ipfw and ipf action templates are not shipped, and `fwknop-convert` warns about legacy pf and ipfw settings instead of pointing at a template.

The goal is a drop-in replacement whose behaviour can be checked against the Go binaries. Each of these could be added later as its own decision, but none should be added just because C has it. We do fix clear bugs in the Go code, and every behaviour that differs from Go is listed in the deviations document.
