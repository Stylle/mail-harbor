# Automatic single-container startup · v0.2.4

Supersedes the v0.2.3 two-service deployment. The image entrypoint prepares ownership internally, drops supplementary groups/GID/UID to10001, sets no_new_privs and execs the separate mail executable. No API/network listener or user-selected executable runs before the drop. Kernel exec removes permitted/effective capabilities; container tests assert UID10001, CapEff0, CapPrm0 and NoNewPrivs1.

The startup helper only inspects the dedicated data root and four fixed key/SQLite files, rejecting system directories, symbolic/hard links, special files and nested mounts. It does not recurse, rewrite existing bytes/modes or regenerate missing keys for existing databases. A custom nonroot Docker user bypasses ownership setup and retains the caller's identity.

Ordinary Compose/docker run with a volume or dedicated bind mount works without a second service. The provided hardened Compose limits startup capabilities to CHOWN/DAC_OVERRIDE/SETUID/SETGID; none survive into the API. Explicit host ACL/read-only/root-squash restrictions cannot be bypassed. Migrating from v0.2.3 retains the original volume and removes the separate service configuration; no volume deletion is needed.

Regression covers the user's single-service pattern, root-owned755 fresh folders, root-owned600 existing files, original key retention across restarts, missing-key safe failure, explicit nonroot user, restricted bootstrap capabilities, safe link/path handling and both published architectures.
