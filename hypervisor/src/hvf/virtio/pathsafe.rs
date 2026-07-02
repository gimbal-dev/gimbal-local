//! Symlink-safe filesystem opens for untrusted snapshot bundles.
//!
//! A downloaded snapshot bundle is untrusted input (see
//! `docs/security-model.md`, M30.1). A malicious bundle can ship a disk image or
//! overlay file that is really a symlink pointing at a host file
//! (`disks/_disk0.raw -> /etc/passwd`). Opening such a link as the guest's disk
//! *base* would leak host file contents into the guest (read); opening a
//! pre-planted *overlay* symlink would redirect guest disk writes onto a host
//! file (write).
//!
//! These helpers open with `O_NOFOLLOW`, so a symlink at the final path
//! component fails with `ELOOP` instead of escaping the bundle. `O_NOFOLLOW`
//! guards the *final* component only, which is exactly right here: the enclosing
//! `disks/` directory is legitimately a symlink in the per-sandbox workspace
//! model (it points at the trusted read-only base image), but the disk/overlay
//! *file* itself must never be a link.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Open `path` read-only, refusing to follow a symlink at the final component.
pub(crate) fn open_ro_nofollow(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

/// Open `path` read/write, creating it if absent, refusing to follow a symlink
/// at the final component. `truncate` truncates an existing regular file. If
/// `path` already exists as a symlink the open fails with `ELOOP`, so a
/// pre-planted overlay link cannot redirect guest writes onto a host file.
pub(crate) fn open_rw_create_nofollow(path: &Path, truncate: bool) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(truncate)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}
