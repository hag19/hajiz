# hagbox

Rust-based application sandboxing project focused on default-deny isolation for untrusted binaries on Linux.

## Current status
- Initial project structure scaffolded
- Core modules split by concern (CLI, profile, isolation, audit)
- Placeholder profiles, docs, examples, and tests added

## Next steps
1. Implement CLI parsing and profile loading
2. Implement namespace, seccomp, and capability isolation
3. Add resource controls and audit mode

See `README_extracted.md` for the full project specification.
