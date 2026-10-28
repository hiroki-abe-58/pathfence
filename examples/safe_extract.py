"""Extract a tar or zip archive: PathFence checks every name, the kernel confines every write. Linux 5.6+.

    safe_extract("plugin.tar.gz", "/home/u/plugins/new")

It raises `Refused` when it refuses the archive, and then nothing has been written. Everything that
can be checked without reading file contents is checked before `dest` is created:

1. The archive must be one tarfile (with any compression it knows) or zipfile can read. A tar
   archive must have an end-of-archive block where its last member ends: tarfile stops without an
   error at a truncated or invalid header, which would hide the rest of the archive.
2. Only regular files and directories are extracted. Symbolic links, hard links, devices, FIFOs,
   tar members with a negative size, and zip entries marked as one of these, encrypted, compressed
   in a way zipfile cannot read, or whose local header names another file, are refused.
3. Names must be UTF-8 (zip names marked as such, unless ASCII), without NUL or other control
   characters, `\\`, a leading `/`, a drive prefix (`C:`) or a component longer than 255 bytes.
   PathFence must allow every name relative to `dest` (`safe_open.check_all`), and each member is
   created at PathFence's `rel`. So no two members may have the same `rel` unless both are
   directories, and no member may be inside a file member.
4. At most `max_members` members, and at most `max_bytes` bytes of file contents in all.
5. `dest` must not exist, and must be creatable.

Then `dest` is created with mode 0700 (and checked to be the private directory just made). Each
directory is created with mkdirat and opened, one component at a time, with
`openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV)`; each file is created with
`O_CREAT | O_EXCL` and, once written, given mode 0755 if its owner could execute it in the archive
and 0644 otherwise. Owners, times and setuid, setgid or sticky bits are not restored.

It raises `OSError` only after it has created `dest`, and leaves what it wrote there (it is the
caller's to remove). That happens when the kernel refuses, for example a link that another process
put in `dest` (ELOOP for a symlink on the way, EEXIST for anything at the name of a new file),
when the disk is full, and when a member's contents cannot be read (a bad CRC or a corrupt
compressed stream: EIO, chained from the exception tarfile or zipfile raised).
"""
import contextlib
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


def _refuse(name, why, cause=None):
    raise Refused({"decision": "reject", "reason": f"{name!r}: {why}"}) from cause


def _tar_members(t):
    for m in t:
        if not (m.isreg() or m.isdir()):
            _refuse(m.name, f"not a regular file or directory (tar type {m.type!r})")
        if m.size < 0:
            _refuse(m.name, "a negative size")
        yield m.name, m.isdir(), m.size, m.mode & 0o100, m
    # tarfile ends the members at the first header it cannot read; only an end-of-archive block (all
    # zeros) says there are no more.
    t.fileobj.seek(t.offset)
    if t.fileobj.read(tarfile.BLOCKSIZE) != tarfile.NUL * tarfile.BLOCKSIZE:
        _refuse(t.name, f"no end-of-archive block at offset {t.offset} (truncated, or an invalid header)")


def _zip_members(z):
    for i in z.infolist():
        mode = i.external_attr >> 16
        if stat.S_IFMT(mode) not in (0, stat.S_IFDIR if i.is_dir() else stat.S_IFREG):
            _refuse(i.filename, f"not a regular file or directory (zip mode {mode:o})")
        if i.orig_filename != i.filename:
            _refuse(i.orig_filename, "a NUL in the name (zipfile would cut it there)")
        if i.flag_bits & 0x1:
            _refuse(i.filename, "encrypted")
        if not i.flag_bits & 0x800 and not i.filename.isascii():
            _refuse(i.filename, "not marked as UTF-8")
        if not i.is_dir():
            z.open(i).close()  # reads the local header: another name or an unknown method fails here
        yield i.filename, i.is_dir(), i.file_size, mode & 0o100, i


def _check(members, root, max_members, max_bytes):
    """[(member, PathFence's answer)] for the members, or `Refused`."""
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
        if any(len(c.encode()) > 255 for c in name.split("/")):
            _refuse(name, "a component longer than 255 bytes")
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
    return list(zip(found, results))


def _dirs(fd, parts):
    """A descriptor for the directory `parts` beneath `fd`, creating what is missing, one component at
    a time. A symlink or a mount point on the way makes openat2 fail."""
    fd = os.dup(fd)
    try:
        for c in parts:
            try:
                os.mkdir(c, 0o755, dir_fd=fd)
            except FileExistsError:
                pass
            fd, parent = safe_open.openat2(fd, c, os.O_PATH | os.O_DIRECTORY, resolve=RESOLVE), fd
            os.close(parent)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _copy(src, out, size, budget, name):
    """Copy exactly `size` bytes, and no more than `budget`; return `size`. (tarfile and zipfile
    already stop at the size; this does not rely on it.)"""
    left = size
    while chunk := src.read(min(left, 1 << 20) or 1):  # at the stated end, try one more byte
        left -= len(chunk)
        if left < 0 or size - left > budget:
            raise OSError(errno.EFBIG, "more data than the stated size or the size limit", name)
        out.write(chunk)
    if left:
        raise OSError(errno.EIO, "less data than the stated size", name)
    return size


def _write(todo, open_member, parent, base, max_bytes):
    # Through openat2, so that a kernel without it fails here, before anything is created.
    try:
        pfd = safe_open.openat2(AT_FDCWD, parent, os.O_PATH | os.O_DIRECTORY, resolve=0)
    except OSError as e:
        _refuse(parent, f"cannot open it ({e})", e)
    try:
        try:
            os.mkdir(base, 0o700, dir_fd=pfd)
        except OSError as e:
            _refuse(os.path.join(parent, base), f"cannot create it ({e})", e)
        dfd = safe_open.openat2(pfd, base, os.O_PATH | os.O_DIRECTORY, resolve=RESOLVE)
    finally:
        os.close(pfd)
    try:
        st = os.fstat(dfd)
        if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077:
            raise OSError(errno.EPERM, "not the private directory just created", os.path.join(parent, base))
        left = max_bytes
        for (name, is_dir, size, exe, handle), r in todo:
            parts = [] if r["rel"] == "." else r["rel"].split("/")
            if is_dir:
                os.close(_dirs(dfd, parts))
                continue
            fd = _dirs(dfd, parts[:-1])
            try:
                out = safe_open.openat2(fd, parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, resolve=RESOLVE)
            finally:
                os.close(fd)
            with os.fdopen(out, "wb") as f:
                try:
                    with open_member(handle) as src:
                        left -= _copy(src, f, size, left, name)
                except OSError:
                    raise
                except Exception as e:  # a bad CRC, a corrupt compressed stream
                    raise OSError(errno.EIO, f"cannot read it from the archive ({e})", name) from e
                os.fchmod(f.fileno(), 0o755 if exe else 0o644)
    finally:
        os.close(dfd)


def safe_extract(archive, dest, max_members=10_000, max_bytes=1 << 30):
    """Extract the archive at the path `archive` into the new directory `dest`. Raises `Refused`, and
    then nothing has been written, or `OSError`, and then `dest` holds what was written."""
    if not sys.platform.startswith("linux"):
        _refuse(archive, "safe_extract needs Linux 5.6 or later (openat2)")
    dest = os.path.abspath(dest)
    parent, base = os.path.realpath(os.path.dirname(dest)), os.path.basename(dest)
    root = os.path.join(parent, base)  # canonical, as PathFence requires
    with contextlib.ExitStack() as stack:
        try:
            if zipfile.is_zipfile(archive):
                z = stack.enter_context(zipfile.ZipFile(archive))
                members, open_member = _zip_members(z), z.open
            else:
                t = stack.enter_context(tarfile.open(archive))
                members, open_member = _tar_members(t), t.extractfile
            todo = _check(members, root, max_members, max_bytes)
        except Refused:
            raise
        except Exception as e:  # not an archive, or one tarfile or zipfile cannot read
            _refuse(archive, f"cannot be read ({e})", e)
        _write(todo, open_member, parent, base, max_bytes)
