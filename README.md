# hajiz

Rust-based application sandboxing project focused on default-deny isolation for untrusted binaries on Linux.

## Current status

- Child pre-exec isolation pipeline is active for command execution.
- Implemented isolation primitives:
  - Linux namespaces (mount, IPC, UTS, optional network namespace isolation)
  - Capability hardening (`no_new_privs`, ambient clear, effective/permitted/inheritable clear, bounding-set drop)
  - Landlock filesystem path restrictions
  - Seccomp enforcement (strict mode, allowlist mode, and hardening-deny mode)
- Hardening seccomp mode blocks high-risk syscalls commonly involved in namespace/capability abuse paths (`unshare`, `setns`, `clone3`, `bpf`, `userfaultfd`, keyring syscalls).

## Security note (Landlock RFC compatibility)

Recent Landlock RFC work proposes first-class namespace/capability permissions in kernel Landlock ABI 9.
This project currently targets stable kernels where these hooks are not generally available yet.

Current equivalent approach:

- Keep namespace isolation in the sandbox launcher
- Enforce Landlock for filesystem access control
- Strip capabilities aggressively in-process
- Deny namespace re-entry and related escalation primitives with seccomp hardening

When Landlock ABI 9 becomes broadly available, this policy can migrate from seccomp-based fallback to native Landlock namespace/capability permissions.

## Quick examples

```bash
hajiz /usr/bin/echo hello
hajiz /usr/bin/id
```

## Next steps

1. Add structured security telemetry (denials, policy hash, process metadata)
2. Build exploit-oriented validation tests against targeted bug classes
3. Add kernel-version capability detection and behavior matrix tests

See `docs/project-spec.md` for the full project specification.
