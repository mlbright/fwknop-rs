# Actions keep Go's `{{.Name}}` placeholder syntax, and nothing more of `text/template`

fwknop-rs is a drop-in replacement for fwknop-go, so existing action templates and inline `actions:` (written like `iptables -A FWKNOP_INPUT -s {{.SourceIP}} …`) must work unchanged. We therefore parse Go-style placeholders even though this is a Rust codebase. We support only `{{.Name}}` (spaces inside the braces allowed) for the known placeholder names. Anything else (`{{if}}`, pipelines, functions, unknown names) stops the server at startup with an error that names the action. Every shipped action template uses only plain placeholders, and Go itself rejects an unknown name only once a packet arrives.

## Considered Options

- **A Rust template engine (minijinja, tera, handlebars)**: its syntax (`{{ source_ip }}`) would break every existing action template.
- **Reimplementing more of `text/template` (if/else, pipelines)**: nothing shipped uses it, and every extra construct is more parsing in the code that builds shell commands from client-supplied data.
