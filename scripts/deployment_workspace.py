"""Ownership and cleanup of the disposable deployment smoke workspace."""

from __future__ import annotations

import contextlib
import os
import sys
import tempfile
from collections.abc import Iterator


def terraform_user_args() -> list[str]:
    """Keep bind-mounted Terraform files owned by the process that cleans them up.

    Linux enforces the container's numeric UID/GID on the host bind mount. Docker
    Desktop on Windows manages mount access itself; use an unprivileged container
    identity there without relying on POSIX-only Python APIs.
    """
    if sys.platform == "win32":
        identity = "1000:1000"
    else:
        identity = f"{os.getuid()}:{os.getgid()}"
    return ["--user", identity]


@contextlib.contextmanager
def deployment_directory() -> Iterator[str]:
    """Use normal TemporaryDirectory cleanup, keeping deployment failures primary.

    Ownership is fixed at the Terraform container boundary. No permission repair,
    symlink traversal or shared-cache cleanup is needed here.
    """
    directory = tempfile.TemporaryDirectory(prefix="asic-deployment-")
    primary: BaseException | None = None
    try:
        yield directory.name
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            directory.cleanup()
        except OSError as error:
            diagnostic = f"deployment workspace cleanup failed ({directory.name}): {error}"
            if primary is None:
                error.add_note(diagnostic)
                raise
            primary.add_note(diagnostic)
