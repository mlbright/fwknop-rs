# fwknop-rs

A Rust implementation of [fwknop](https://www.cipherdyne.org/fwknop/)
(FireWall KNock OPerator) — Single Packet Authorization (SPA) for strong
service concealment — translated from
[fwknop-go](https://github.com/mlbright/fwknop-go) and compatible with the C
and Go implementations (SPA protocol 3.0.0).

Work in progress. See [GLOSSARY.md](GLOSSARY.md) for the project's
vocabulary, [docs/adr/](docs/adr/) for its key decisions and
[docs/deviations-from-go.md](docs/deviations-from-go.md) for how it differs
from fwknop-go.

## License

GNU General Public License v2.0 — see [LICENSE](LICENSE). fwknop-rs is a
translation of fwknop-go, which is itself derived from C fwknop; both are
licensed under the GPL v2.
