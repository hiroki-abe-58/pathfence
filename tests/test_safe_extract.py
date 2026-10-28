"""examples/safe_extract.py: links, special files, bad names and unreadable archives are refused;
writes stay in dest.

Every archive is built here, in a temporary directory that also holds `outside/secret`, next to
where `dest` will be. A refused archive must leave no trace: no `dest`, nothing new anywhere in the
temporary directory, the secret unchanged. The kernel tests then plant links in `dest` while it is
being extracted, as another process could, and check that openat2 refuses them, with an OSError
and nothing outside `dest` changed. Linux 5.6+; elsewhere only the refusal to run is tested.
"""
import errno
import io
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import warnings
import zipfile
from unittest import mock

from common import BIN, ROOT
from test_kernel import openat2_available

sys.path.insert(0, os.path.join(ROOT, "examples"))
import safe_extract  # noqa: E402
import safe_open  # noqa: E402

safe_open.PATHFENCE = BIN
Refused = safe_open.Refused
TYPES = {"f": tarfile.REGTYPE, "d": tarfile.DIRTYPE, "l": tarfile.SYMTYPE, "h": tarfile.LNKTYPE,
         "c": tarfile.CHRTYPE, "b": tarfile.BLKTYPE, "p": tarfile.FIFOTYPE}


def make_tar(path, members, mode="w"):
    """members: ("f", name, data[, mode]), ("d", name), ("l" or "h", name, target), ("c"/"b"/"p", name)."""
    with tarfile.open(path, mode) as t:
        for kind, name, *rest in members:
            m = tarfile.TarInfo(name)
            m.type = TYPES[kind]
            data = rest[0] if kind == "f" else b""
            m.size = len(data)
            m.mode = rest[1] if kind == "f" and len(rest) > 1 else 0o755 if kind == "d" else 0o644
            if kind in "lh":
                m.linkname = rest[0]
            t.addfile(m, io.BytesIO(data) if kind == "f" else None)


def make_zip(path, entries):
    """entries: (name, data[, unix mode with file type bits]); a name ending in / is a directory."""
    with warnings.catch_warnings(), zipfile.ZipFile(path, "w") as z:
        warnings.simplefilter("ignore")  # duplicate names
        for name, data, *mode in entries:
            i = zipfile.ZipInfo(name)
            i.external_attr = (mode[0] if mode else 0o644) << 16
            z.writestr(i, data)


def patch_bytes(path, old, new):
    with open(path, "rb") as f:
        b = f.read()
    assert old in b
    with open(path, "wb") as f:
        f.write(b.replace(old, new))


def patch_zip(path, local, central, change):
    """Apply `change` to a 2-byte field: at offset `local` in every local header, and `central` in
    every central directory header (None leaves those alone). zipfile writes these fields itself."""
    with open(path, "rb") as f:
        b = bytearray(f.read())
    for sig, off in ((b"PK\x03\x04", local), (b"PK\x01\x02", central)):
        i = b.find(sig)
        while off is not None and i >= 0:
            b[i + off:i + off + 2] = change(int.from_bytes(b[i + off:i + off + 2], "little")).to_bytes(2, "little")
            i = b.find(sig, i + 4)
    with open(path, "wb") as f:
        f.write(b)


def patch_tar_header(path, offset, field, value):
    """Overwrite a field of the tar header at `offset`, and recompute its checksum."""
    with open(path, "r+b") as f:
        f.seek(offset)
        h = bytearray(f.read(512))
        h[field:field + len(value)] = value
        h[148:156] = b" " * 8
        h[148:156] = b"%06o\0 " % sum(h)
        f.seek(offset)
        f.write(h)


def listing(top):
    """Every path below `top`, not following symlinks: its type, and for files, mode and contents."""
    out = {}
    for d, dirs, files in os.walk(top):
        for n in dirs + files:
            p = os.path.join(d, n)
            st = os.lstat(p)
            if stat.S_ISREG(st.st_mode):
                with open(p, "rb") as f:
                    out[os.path.relpath(p, top)] = ("f", stat.S_IMODE(st.st_mode), f.read())
            else:
                out[os.path.relpath(p, top)] = ("d",) if stat.S_ISDIR(st.st_mode) else (oct(st.st_mode),)
    return out


def open_fds():
    return len(os.listdir("/proc/self/fd"))


@unittest.skipUnless(openat2_available(), "openat2 is not available")
class SafeExtract(unittest.TestCase):
    def setUp(self):
        self.top = os.path.realpath(tempfile.mkdtemp())
        self.out = os.path.join(self.top, "outside")
        os.mkdir(self.out)
        with open(os.path.join(self.out, "secret"), "w") as f:
            f.write("secret\n")
        self.dest = os.path.join(self.top, "dest")
        self.n = 0

    def tearDown(self):
        shutil.rmtree(self.top)

    def archive(self, members, kind="tar"):
        self.n += 1
        path = os.path.join(self.top, f"archive{self.n}.{kind}")
        if kind == "zip":
            make_zip(path, members)
        else:
            make_tar(path, members, {"tar": "w", "tgz": "w:gz"}[kind])
        return path

    def assertRefused(self, path, why="", **kw):
        before = listing(self.top)
        with self.assertRaises(Refused) as e:
            safe_extract.safe_extract(path, self.dest, **kw)
        self.assertIn(why, str(e.exception))
        self.assertEqual(listing(self.top), before)  # no dest, nothing new, the secret unchanged

    def test_extracts_regular_files_and_directories(self):
        tar = [("d", "."), ("f", "./a/b.txt", b"hello"), ("d", "a"), ("d", "a"), ("f", "a/./c/../d", b"d"),
               ("f", "\u00e9/x", b"x"), ("f", "bin/run", b"#!", 0o4755), ("f", "bin/data", b"", 0o2640),
               ("d", "e/f/g"), ("f", "a//s p", b"s")]
        zip_ = [("a/", b""), ("a/b.txt", b"hello"), ("a/./c/../d", b"d"), ("\u00e9/x", b"x"),
                ("bin/run", b"#!", stat.S_IFREG | 0o4755), ("bin/data", b"", 0o640), ("e/f/g/", b"", stat.S_IFDIR | 0o755),
                ("a//s p", b"s")]
        want = {"a": ("d",), "a/b.txt": ("f", 0o644, b"hello"), "a/d": ("f", 0o644, b"d"), "\u00e9": ("d",),
                "\u00e9/x": ("f", 0o644, b"x"), "bin": ("d",), "bin/run": ("f", 0o755, b"#!"),
                "bin/data": ("f", 0o644, b""), "e": ("d",), "e/f": ("d",), "e/f/g": ("d",), "a/s p": ("f", 0o644, b"s")}
        for kind, members in (("tar", tar), ("tgz", tar), ("zip", zip_)):
            with self.subTest(kind=kind):
                dest = os.path.join(self.top, "dest-" + kind)
                safe_extract.safe_extract(self.archive(members, kind), dest)
                self.assertEqual(listing(dest), want)
                self.assertEqual(stat.S_IMODE(os.lstat(dest).st_mode) & 0o077, 0)  # private while extracted

    def test_more_members_than_one_pathfence_run_takes(self):
        n = 2 * safe_extract.CHUNK + 1
        safe_extract.safe_extract(self.archive([("f", f"d/{i}", b"%d" % i) for i in range(n)]), self.dest)
        self.assertEqual(listing(self.dest), {"d": ("d",), **{f"d/{i}": ("f", 0o644, b"%d" % i) for i in range(n)}})

    def test_refuses_links_devices_and_fifos(self):
        ok = ("f", "a", b"x")
        for members in ([ok, ("l", "l", "a")], [("l", "l", "/etc")], [ok, ("h", "h", "a")],
                        [ok, ("c", "c")], [ok, ("b", "b")], [ok, ("p", "p")]):
            with self.subTest(members=members):
                self.assertRefused(self.archive(members), "not a regular file")
        for mode in (stat.S_IFLNK | 0o777, stat.S_IFIFO | 0o644, stat.S_IFCHR | 0o644, stat.S_IFBLK | 0o644,
                     stat.S_IFSOCK | 0o644, stat.S_IFDIR | 0o755):  # the last: a directory mode on a file name
            with self.subTest(zip_mode=oct(mode)):
                self.assertRefused(self.archive([("a", b"x"), ("l", b"/etc/passwd", mode)], "zip"), "not a regular")
        with self.subTest("encrypted zip entry"):
            path = self.archive([("a", b"x")], "zip")
            patch_zip(path, 6, 8, lambda flags: flags | 0x1)
            self.assertRefused(path, "encrypted")

    def test_cve_2025_4517_structure(self):
        # The members of the proof of concept in GHSA-hgqp-3mmf-7h8f, with 4 levels instead of 16:
        # symlinks whose expansion is longer than PATH_MAX, a link out through them, a hard link to a
        # file outside, then regular files written through both.
        members, path = [], ""
        for c in "abcd":
            members += [("d", path + "d" * 200), ("l", path + c, "d" * 200)]
            path += c + "/"
        members += [("l", path + "l" * 200, "../" * 4), ("l", "escape", path + "l" * 200 + "/../outside"),
                    ("h", "flaglink", "escape/secret"), ("f", "flaglink", b"overwrite"),
                    ("f", "escape/newfile", b"new!")]
        self.assertRefused(self.archive(members), "not a regular file")

    def test_refuses_names_that_leave_dest_or_are_not_portable(self):
        for name in ["../x", "../evil/../dest/sub/f", "a/../../dest/f", "..", "/abs", self.dest + "/f",
                     "a\\b", "..\\x", "C:x", "c:/x", "a\nb", "a\rb", "a\tb", "a\x7fb", "a\x85b", "a\udcffb",
                     "d" * 256 + "/x", "x/" + "\u00e9" * 128]:
            with self.subTest(tar_name=name):
                self.assertRefused(self.archive([("f", "ok", b"1"), ("f", name, b"x")]))
        for name in ["../zx", "/zabs", "a\\..\\..\\zb", "C:/zc"]:
            with self.subTest(zip_name=name):
                self.assertRefused(self.archive([("ok", b"1"), (name, b"x")], "zip"))
        with self.subTest("a non-ASCII zip name not marked as UTF-8"):
            path = self.archive([("ok", b"1"), ("\u00e9", b"x")], "zip")
            patch_zip(path, 6, 8, lambda flags: flags & ~0x800)
            self.assertRefused(path, "UTF-8")
        with self.subTest("a zip name with a NUL, which zipfile would cut to `a`"):
            path = self.archive([("ok", b"1"), ("aX../x", b"x")], "zip")
            patch_bytes(path, b"aX../x", b"a\x00../x")
            self.assertRefused(path, "NUL")

    def test_refuses_duplicates_and_members_inside_files(self):
        for members in ([("f", "a", b"1"), ("f", "a", b"2")], [("f", "a", b"1"), ("d", "a")],
                        [("d", "a"), ("f", "a", b"1")], [("f", "b", b"1"), ("f", "a/../b", b"2")],
                        [("f", "a", b"1"), ("f", "a/b", b"2")], [("f", "a", b"1"), ("d", "a/b/c")],
                        [("f", ".", b"1")], [("f", "x/..", b"1")]):
            with self.subTest(members=members):
                self.assertRefused(self.archive(members))
        for entries in ([("a", b"1"), ("a", b"2")], [("d/", b""), ("d", b"1")]):
            with self.subTest(zip=entries):
                self.assertRefused(self.archive(entries, "zip"))

    def test_limits(self):
        path = self.archive([("f", "a", b"123"), ("d", "d"), ("f", "d/b", b"456")])
        self.assertRefused(path, "members", max_members=2)
        self.assertRefused(path, "bytes", max_bytes=5)
        safe_extract.safe_extract(path, self.dest, max_members=3, max_bytes=6)
        self.assertEqual(listing(self.dest), {"a": ("f", 0o644, b"123"), "d": ("d",), "d/b": ("f", 0o644, b"456")})
        long = "d" * 255  # NAME_MAX: the longest component that is accepted
        safe_extract.safe_extract(self.archive([("f", long + "/x", b"1")]), self.dest + "2")
        self.assertEqual(listing(self.dest + "2"), {long: ("d",), long + "/x": ("f", 0o644, b"1")})

    def test_refuses_archives_it_cannot_read_completely(self):
        # A tar archive with 1000 and 5000 bytes of contents: headers at 0 and 1536, end at 7168.
        def tar(change):
            path = self.archive([("f", "a", b"A" * 1000), ("f", "b", b"B" * 5000)])
            with open(path, "r+b") as f:
                change(f)
            return path

        for what, path, why in (
                ("not an archive", self.archive([("f", "x", b"")]) + ".txt", "cannot be read"),
                ("no such file", os.path.join(self.top, "missing.tar"), "cannot be read"),
                ("an empty file", tar(lambda f: f.truncate(0)), "cannot be read"),
                ("tar data cut short", tar(lambda f: f.truncate(4048)), "cannot be read"),
                # Where tarfile itself stops without an error:
                ("a tar header cut short", tar(lambda f: f.truncate(1636)), "end-of-archive"),
                ("no end-of-archive block", tar(lambda f: f.truncate(7168)), "end-of-archive"),
                ("garbage instead of a header", tar(lambda f: (f.seek(7168), f.write(b"X" * 512))), "end-of-archive"),
                ("a gzip stream cut short", self.archive([("f", "a", os.urandom(50000))], "tgz"), "cannot be read")):
            with self.subTest(what):
                if what == "not an archive":
                    with open(path, "w") as f:
                        f.write("hello\n")
                if what == "a gzip stream cut short":
                    with open(path, "r+b") as f:
                        f.truncate(os.path.getsize(path) // 2)
                self.assertRefused(path, why)

    def test_refuses_a_negative_tar_size(self):
        # Base-256 -512 in the size field of `n`, the second header. For a regular file, Pythons with
        # the fix for CVE-2025-8194 stop at the header themselves (it would make the next header come
        # before this one); for a directory the size is not used, and only safe_extract refuses it.
        for member, why in ((("f", "n", b"y"), ""), (("d", "n"), "negative")):
            with self.subTest(member=member):
                path = self.archive([("f", "a", b"x"), member])
                patch_tar_header(path, 1024, 124, b"\xff" + (256 ** 11 - 512).to_bytes(11, "big"))
                self.assertRefused(path, why)

    def test_refuses_zip_entries_zipfile_cannot_read(self):
        with self.subTest("a local header that names another file"):
            path = self.archive([("n1", b"x")], "zip")
            with open(path, "r+b") as f:
                f.seek(30)  # the name in the first local header
                f.write(b"n2")
            self.assertRefused(path, "cannot be read")
        with self.subTest("an unknown compression method"):
            path = self.archive([("n1", b"x")], "zip")
            patch_zip(path, None, 10, lambda method: 97)
            self.assertRefused(path, "cannot be read")

    def test_a_bad_crc_is_an_oserror_after_the_members_before_it(self):
        path = self.archive([("a", b"AAAA"), ("b", b"BBBB"), ("c", b"CCCC")], "zip")
        patch_bytes(path, b"BBBB", b"BBBC")
        before = listing(self.out)
        with self.assertRaises(OSError) as e:
            safe_extract.safe_extract(path, self.dest)
        self.assertEqual(e.exception.errno, errno.EIO)
        self.assertIsInstance(e.exception.__cause__, zipfile.BadZipFile)
        got = listing(self.dest)
        self.assertEqual(sorted(got), ["a", "b"])  # `b` was being written when the CRC failed
        self.assertEqual(got["a"], ("f", 0o644, b"AAAA"))
        self.assertEqual(listing(self.out), before)

    def test_dest_must_not_exist(self):
        path = self.archive([("f", "secret", b"x")])
        for make in (os.mkdir, lambda d: os.symlink(self.out, d)):
            with self.subTest(make=make):
                make(self.dest)
                self.assertRefused(path, "cannot create it")
                os.remove(self.dest) if os.path.islink(self.dest) else os.rmdir(self.dest)

    def test_an_unusable_pathfence_answer_refuses_before_writing(self):
        path = self.archive([("f", "a", b"x")])
        with mock.patch.object(safe_open.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 0, b"not json\n", b"")):
            self.assertRefused(path, "pathfence")
        with mock.patch.object(safe_open, "PATHFENCE", os.path.join(self.top, "no-such-binary")):
            self.assertRefused(path, "pathfence")

    def test_a_directory_replaced_by_a_symlink_is_not_followed(self):
        # Another process swaps `sub` for a symlink between its creation and its opening.
        real_mkdir = os.mkdir
        for k, target in enumerate((self.out, "../outside", "other")):
            dest = os.path.join(self.top, f"dest{k}")

            def mkdir_then_swap(name, mode=0o777, *, dir_fd=None):
                real_mkdir(name, mode, dir_fd=dir_fd)
                if name == "sub":
                    os.rmdir(os.path.join(dest, "sub"))
                    os.symlink(target, os.path.join(dest, "sub"))

            with self.subTest(target=target), mock.patch.object(safe_extract.os, "mkdir", mkdir_then_swap):
                before, fds = listing(self.out), open_fds()
                with self.assertRaises(OSError) as e:
                    safe_extract.safe_extract(self.archive([("d", "other"), ("f", "sub/f", b"x")]), dest)
                self.assertEqual(e.exception.errno, errno.ELOOP)
                self.assertEqual(listing(self.out), before)
                self.assertEqual(os.listdir(os.path.join(dest, "other")), [])
                self.assertEqual(open_fds(), fds)

    def test_no_descriptor_is_left_open_when_a_directory_cannot_be_made(self):
        real_mkdir = os.mkdir

        def mkdir_fails(name, mode=0o777, *, dir_fd=None):
            if name == "c":
                raise PermissionError(errno.EACCES, "denied", name)
            real_mkdir(name, mode, dir_fd=dir_fd)

        fds = open_fds()
        with mock.patch.object(safe_extract.os, "mkdir", mkdir_fails), self.assertRaises(PermissionError):
            safe_extract.safe_extract(self.archive([("f", "a/b/c/d", b"x")]), self.dest)
        self.assertEqual(open_fds(), fds)

    def test_a_replaced_dest_is_noticed(self):
        # Another process puts a directory others can write to where dest was just created.
        real_mkdir = os.mkdir

        def mkdir_then_replace(name, mode=0o777, *, dir_fd=None):
            real_mkdir(name, mode, dir_fd=dir_fd)
            if name == "dest":
                os.rmdir(self.dest)
                real_mkdir(self.dest)
                os.chmod(self.dest, 0o777)

        path = self.archive([("f", "f", b"x")])
        with mock.patch.object(safe_extract.os, "mkdir", mkdir_then_replace), self.assertRaises(OSError) as e:
            safe_extract.safe_extract(path, self.dest)
        self.assertEqual(e.exception.errno, errno.EPERM)
        self.assertEqual(os.listdir(self.dest), [])

    def test_a_link_planted_at_a_new_file_is_not_written_through(self):
        # Another process puts a hard link or a symlink where the next file is about to be created.
        secret, new = os.path.join(self.out, "secret"), os.path.join(self.out, "new")
        real_openat2 = safe_open.openat2
        plants = {"hard link to the secret": lambda p: os.link(secret, p),
                  "symlink to the secret": lambda p: os.symlink(secret, p),
                  "dangling symlink out of dest": lambda p: os.symlink(new, p)}
        for k, (what, plant) in enumerate(plants.items()):
            dest = os.path.join(self.top, f"dest{k}")

            def plant_then_open(dirfd, path, flags, *args, **kw):
                if flags & os.O_CREAT:
                    plant(os.path.join(dest, path))
                return real_openat2(dirfd, path, flags, *args, **kw)

            with self.subTest(what), mock.patch.object(safe_open, "openat2", plant_then_open):
                before, fds = listing(self.out), open_fds()
                with self.assertRaises(OSError) as e:
                    safe_extract.safe_extract(self.archive([("f", "f", b"overwritten")]), dest)
                self.assertEqual(e.exception.errno, errno.EEXIST)
                self.assertEqual(listing(self.out), before)
                self.assertEqual(open_fds(), fds)


class Copy(unittest.TestCase):
    def test_copies_exactly_the_size_and_no_more_than_the_budget(self):
        out = io.BytesIO()
        self.assertEqual(safe_extract._copy(io.BytesIO(b"x" * 10), out, 10, 10, "n"), 10)
        self.assertEqual(out.getvalue(), b"x" * 10)
        for data, size, budget, err in ((b"x" * 10, 10, 9, errno.EFBIG), (b"x" * 11, 10, 20, errno.EFBIG),
                                        (b"x" * 9, 10, 20, errno.EIO)):
            with self.subTest(data=len(data), size=size, budget=budget), self.assertRaises(OSError) as e:
                safe_extract._copy(io.BytesIO(data), io.BytesIO(), size, budget, "n")
            self.assertEqual(e.exception.errno, err)


class OffLinux(unittest.TestCase):
    def test_refuses_to_run_without_writing(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, "a.tar")
            make_tar(path, [("f", "a", b"x")])
            with mock.patch.object(safe_extract.sys, "platform", "darwin"), self.assertRaises(Refused) as e:
                safe_extract.safe_extract(path, os.path.join(tmp, "dest"))
            self.assertIn("needs Linux", str(e.exception))
            self.assertEqual(os.listdir(tmp), ["a.tar"])
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main()
