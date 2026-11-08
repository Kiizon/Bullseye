"""Import this first in scripts that load transformers.

Inside a restricted sandbox, some files (e.g. *.pem certificate bundles under
the home folder) raise PermissionError on stat() instead of being readable.
transformers scans installed package files at import time and crashes on that.
Treat an unreadable file as absent. No effect on a normal machine.
"""
import pathlib

_orig_exists = pathlib.Path.exists


def _exists(self, *args, **kwargs):
    try:
        return _orig_exists(self, *args, **kwargs)
    except PermissionError:
        return False


pathlib.Path.exists = _exists
