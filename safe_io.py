"""Bounded reads of regular files and single-hop HTTPS responses."""
import os
import stat
from urllib.request import HTTPRedirectHandler, build_opener


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def open_https(request, *, timeout):
    return build_opener(NoRedirects()).open(request, timeout=timeout)


def read_regular(path, limit, *, dir_fd=None):
    """Reject special files; bound the actual read even if a file grows."""
    before = os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode):
        raise OSError("Not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags, dir_fd=dir_fd)
    with os.fdopen(fd, "rb") as stream:
        current = os.fstat(stream.fileno())
        if not stat.S_ISREG(current.st_mode) or (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
            raise OSError("File changed while opening")
        if current.st_size > limit:
            raise ValueError("File size limit exceeded")
        raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise ValueError("File size limit exceeded")
        return raw
