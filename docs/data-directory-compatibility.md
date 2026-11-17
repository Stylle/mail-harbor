# Writable mount compatibility

Included in v0.2.1.

Startup no longer chmods an existing DATA_DIR or database. The old unconditional chmod rejected writable NAS/bind mounts when the unprivileged process did not own the path. Existing host modes and ACLs are retained; new key/database files are created with restrictive modes. The service remains UID/GID10001, read-only root compatible and cap_drop ALL; no startup ownership helper or extra capabilities were added.

The default Compose uses a Docker-managed named volume, requiring no manually created host folder. A custom bind mount still must actually permit the selected container user to read/write SQLite files and its WAL/SHM; read-only mounts and host ACL denial cannot be bypassed. Keep the current data mount when upgrading; do not switch to a fresh empty volume to mask a permissions issue.

Reproduced in isolated Docker tmpfs owned by root with group write permission: old v0.2.0 exits, fixed image starts as UID10001 without changing mode0770. Linux tests also verify preservation of existing directory/database modes and private new keys. Full Go tests/vet and Linux race passed. No business volume was replaced or cleared.
