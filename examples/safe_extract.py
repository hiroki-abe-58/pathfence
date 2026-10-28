"""Extract a tar or zip archive: PathFence checks every name, the kernel confines every write. Linux 5.6+.

    safe_extract("plugin.tar.gz", "/home/u/plugins/new")

Everything that can be checked without reading file contents is checked before anything is written,
and any refusal (`Refused`) refuses the whole archive:

1. Only regular files and directories are extracted. Symbolic links, hard links, devices, FIFOs, and
   zip entries marked as one of these or encrypted are refused.
2. Names must be UTF-8 (zip names marked as such, unless ASCII), without control characters, `\\`, a
   leading `/` or a drive prefix (`C:`). PathFence must allow every name relative to `dest`
   (`safe_open.check_all`), and each member is created at PathFence's `rel`. So no two members may
   have the same `rel` unless both are directories, and no member may be inside a file member.
3. At most `max_members` members, and at most `max_bytes` bytes of file contents in all.

Then `dest`, which must not exist, is created with mode 0700. Each directory is created with
mkdirat and opened, one component at a time, with `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
RESOLVE_NO_XDEV)`; each file is created with `O_CREAT | O_EXCL` and, once written, given mode 0755
if its owner could execute it in the archive and 0644 otherwise. Owners, times and setuid, setgid
or sticky bits are not restored.

The archive cannot contain links, so nothing in it can redirect a later member. A link that appears
in `dest` anyway, made by another process, makes openat2 fail with ELOOP (a symlink on the way) or
EEXIST (anything at the name of a new file) instead of being followed or written through. Such an
OSError, or an error reading a member's contents (a truncated archive, a bad CRC), is raised after
some members may have been written: what was written is left in `dest`.
"""
import errno
import os
import re
import stat
import sys
import tarfile
import unicodedata
import zipfile

import safe_open
from safe_open import Refused

RESOLVE = safe_open.RESOLVE_BENEATH | safe_open.RESOLVE_NO_SYMLINKS | 0x01  # | RESOLVE_NO_XDEV
AT_FDCWD = -100
CHUNK = 256  # names per `pathfence check` run, to stay well within the command-line size limit


def _refuse(name, why):
    raise Refused({"decision": "reject", "reason": f"{name!r}: {why}"})


def _tar_members(t):
    for m in t:
        if not (m.isreg() or m.isdir()):
            _refuse(m.name, f"not a regular file or directory (tar type {m.type!r})")
        yield m.name, m.isdir(), m.size, m.mode & 0o100, m


def _zip_members(z):
    for i in z.infolist():
        mode = i.external_attr >> 16
        if stat.S_IFMT(mode) not in (0, stat.S_IFDIR if i.is_dir() else stat.S_IFREG):
            _refuse(i.filename, f"not a regular file or directory (zip mode {mode:o})")
        if i.flag_bits & 0x1:
            _refuse(i.filename, "encrypted")
        if not i.flag_bits & 0x800 and not i.filename.isascii():
            _refuse(i.filename, "not marked as UTF-8")
        yield i.filename, i.is_dir(), i.file_size, mode & 0o100, i


def _dirs(fd, parts):
    """A descriptor for the directory `parts` beneath `fd`, creating what is missing, one component at
    a time. A symlink or a mount point on the way makes openat2 fail."""
    fd = os.dup(fd)
    for c in parts:
        try:
            os.mkdir(c, 0o755, dir_fd=fd)
        except FileExistsError:
            pass
        try:
            sub = safe_open.openat2(fd, c, os.O_PATH | os.O_DIRECTORY, resolve=RESOLVE)
        finally:
            os.close(fd)
        fd = sub
    return fd


def _copy(src, out, size, name):
    """Copy exactly `size` bytes (tarfile and zipfile already stop there; this does not rely on it)."""
    left = size
    while chunk := src.read(min(left, 1 << 20) or 1):  # at the stated end, try one more byte
        left -= len(chunk)
        if left < 0:
            raise OSError(errno.EFBIG, "more data than the stated size", name)
        out.write(chunk)
    if left:
        raise OSError(errno.EIO, "less data than the stated size", name)


def safe_extract(archive, dest, max_members=10_000, max_bytes=1 << 30):
    """Extract `archive` (a path) into the new directory `dest`, or raise `Refused` (nothing is
    written) or `OSError`."""
    if not sys.platform.startswith("linux"):
        raise OSError(errno.ENOSYS, "safe_extract needs Linux 5.6 or later (openat2)")
    dest = os.path.abspath(dest)
    parent, base = os.path.realpath(os.path.dirname(dest)), os.path.basename(dest)
    root = os.path.join(parent, base)  # canonical, as PathFence requires
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as z:
            _extract(_zip_members(z), z.open, parent, base, root, max_members, max_bytes)
    else:
        with tarfile.open(archive) as t:
            _extract(_tar_members(t), t.extractfile, parent, base, root, max_members, max_bytes)


def _extract(members, open_member, parent, base, root, max_members, max_bytes):
    found = []
    for m in members:
        found.append(m)
        if len(found) > max_members:
            _refuse(m[0], f"more than {max_members} members")
    if sum(size for _, is_dir, size, _, _ in found if not is_dir) > max_bytes:
        _refuse(root, f"more than {max_bytes} bytes")
    for name, *_ in found:
        try:
            name.encode("utf-8")
        except UnicodeEncodeError:
            _refuse(name, "not UTF-8")
        if name.startswith("/") or "\\" in name or re.match("[A-Za-z]:", name):
            _refuse(name, "absolute, or a Windows path")
        if any(unicodedata.category(c) == "Cc" for c in name):
            _refuse(name, "a control character")
    names = [m[0] for m in found]
    results = []
    for i in range(0, len(names), CHUNK):
        results += safe_open.check_all(names[i:i + CHUNK], allow=[root])
    seen = {".": True}  # rel -> is it a directory
    for (name, is_dir, *_), r in zip(found, results):
        if r["decision"] != "allow":
            _refuse(name, f"pathfence: {r['decision']} ({r.get('reason') or r.get('path')})")
        if r["rel"] in seen and not (is_dir and seen[r["rel"]]):
            _refuse(name, f"a second member at {r['rel']!r}")
        seen[r["rel"]] = is_dir
    for rel in seen:
        parts = rel.split("/")
        if any(seen.get("/".join(parts[:i])) is False for i in range(1, len(parts))):
            _refuse(rel, "inside a file")

    # Through openat2, so that a kernel without it fails here, before anything is created.
    pfd = safe_open.openat2(AT_FDCWD, parent, os.O_PATH | os.O_DIRECTORY, resolve=0)
    try:
        os.mkdir(base, 0o700, dir_fd=pfd)
        dfd = safe_open.openat2(pfd, base, os.O_PATH | os.O_DIRECTORY, resolve=RESOLVE)
    finally:
        os.close(pfd)
    try:
        for (name, is_dir, size, exe, handle), r in zip(found, results):
            parts = [] if r["rel"] == "." else r["rel"].split("/")
            if is_dir:
                os.close(_dirs(dfd, parts))
                continue
            fd = _dirs(dfd, parts[:-1])
            try:
                out = safe_open.openat2(fd, parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, resolve=RESOLVE)
            finally:
                os.close(fd)
            with os.fdopen(out, "wb") as f, open_member(handle) as src:
                _copy(src, f, size, name)
                os.fchmod(f.fileno(), 0o755 if exe else 0o644)
    finally:
        os.close(dfd)
