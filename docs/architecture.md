# Architecture

Initial architecture follows a modular split:

- `cli`: command-line parsing
- `profile`: TOML schema and parser
- `isolation`: namespaces, seccomp, capabilities, cgroups, network
- `audit`: behavior tracing and profile generation

Detailed design is captured in `README_extracted.md`.
