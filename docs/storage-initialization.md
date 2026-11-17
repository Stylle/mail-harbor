# Storage initialization · v0.2.3

Root cause: the unprivileged service could not create/read master.key on root-owned bind mounts, but both cases were collapsed into the corrupt-key error. v0.2.1 removed chmod without addressing ownership.

Compose now runs the same image's data-init binary once before the mail service. Its network is disabled, it has no API or ports, its root filesystem is read-only, and only CHOWN/DAC_OVERRIDE are available. It inspects the dedicated directory and four fixed key/SQLite paths, rejecting symbolic/hard links, special files and nested mounts before changing ownership. It never recurses or rewrites file contents/modes. The main service remains UID10001 with cap_drop ALL. Successful initialization exits with0.

Fresh volumes initialize normally. Existing keys are preserved and all encrypted settings are checked, including 2FA and channels without mailbox accounts. Missing keys alongside existing databases are never regenerated; key creation is exclusive and fsynced. Invalid key bytes/files are not removed. Explicit errors distinguish permission, invalid file type, invalid length, missing matching key and decryption mismatch.

For existing bind mounts, adopt the new Compose while retaining the original data source; upgrading the image alone does not add the prerequisite service. NAS root-squash/read-only/denied ACLs cannot be bypassed. Restore a matching complete backup if the original key is actually missing or corrupt.

Regression: native unit tests and Linux race/vet, isolated Docker fresh root-owned755 folder, root-owned600 key/database, retained key across restarts, missing-key safe refusal, no API privileges, ownership-only changes, and rejection of symlinks/hard links/FIFOs/directories. No business volume is replaced and no real mail is sent in these checks.
