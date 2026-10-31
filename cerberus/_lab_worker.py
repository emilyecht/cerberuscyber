# Copyright 2026 Emily Echterhoff
# SPDX-License-Identifier: Apache-2.0

"""Closed Linux lab worker, not a general-purpose sandbox or tool runner.

Executed as a fresh interpreter with only the protocol socket inherited. No
signing keys, approvals, or writable target descriptors cross this boundary.
Landlock is installed before accepting any test instruction. This file is also
executable directly so the worker does not need to import the trusted package.
"""

from __future__ import annotations

import ctypes
import errno
import json
import os
import platform
import socket
import subprocess
import sys

MAX_MESSAGE = 65536


class SandboxUnavailable(RuntimeError):
    """The required kernel boundary could not be installed; do not continue."""


def _libc():
    # These syscall numbers are shared by the supported Linux architectures.
    # Unknown architectures are rejected rather than guessing syscall numbers.
    if sys.platform != "linux" or platform.machine() not in ("x86_64", "aarch64"):
        raise SandboxUnavailable("requires Linux x86_64/aarch64 with Landlock ABI >= 3")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    return libc


def landlock_abi() -> int:
    libc = _libc()
    abi = libc.syscall(444, ctypes.c_void_p(), ctypes.c_size_t(0), ctypes.c_uint(1))
    if abi < 3:
        detail = f"errno {ctypes.get_errno()}" if abi < 0 else f"ABI {abi}"
        raise SandboxUnavailable(f"Landlock ABI >= 3 is required, including truncation control ({detail})")
    return int(abi)


def restrict_worker() -> int:
    """Deny new filesystem writes, truncation, removal, creation and exec.

    No allow rules are added. Reads and existing socket I/O remain permitted.
    Require ABI 3 rather than silently dropping the truncation restriction.
    Restrictions affect only this fresh, single-threaded worker and descendants.
    Reference: https://docs.kernel.org/userspace-api/landlock.html
    """
    abi = landlock_abi()
    libc = _libc()
    # ABI 3 filesystem bits 0..14, except READ_FILE (2) and READ_DIR (3).
    handled = ctypes.c_uint64(((1 << 15) - 1) & ~((1 << 2) | (1 << 3)))
    fd = libc.syscall(444, ctypes.byref(handled), ctypes.c_size_t(8), ctypes.c_uint(0))
    if fd < 0:
        raise SandboxUnavailable(f"Landlock ruleset creation failed: errno {ctypes.get_errno()}")
    try:
        if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
            raise SandboxUnavailable("cannot set no_new_privs")
        if libc.syscall(446, ctypes.c_int(fd), ctypes.c_uint(0)) != 0:
            raise SandboxUnavailable(f"Landlock restriction failed: errno {ctypes.get_errno()}")
    finally:
        os.close(fd)
    return abi


def send_message(channel: socket.socket, message: dict) -> None:
    data = json.dumps(message, sort_keys=True, allow_nan=False).encode("utf-8")
    if len(data) > MAX_MESSAGE or channel.send(data) != len(data):
        raise RuntimeError("lab protocol message exceeds bound or was not fully sent")


def receive_message(channel: socket.socket) -> dict:
    data, _, flags, _ = channel.recvmsg(MAX_MESSAGE)
    if not data or flags & socket.MSG_TRUNC:
        raise RuntimeError("lab protocol closed or oversized")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise RuntimeError("lab protocol requires an object")
    return value


def attempt(instruction: dict) -> dict:
    """Attempt fixed fixture operations; never evaluate supplied Python or shell."""
    operation, path = instruction["op"], instruction["path"]
    try:
        if operation == "write":
            with open(path, "wb") as stream:
                stream.write(b"UNAUTHORIZED\n")
        elif operation == "truncate":
            os.truncate(path, 0)
        elif operation == "unlink":
            os.unlink(path)
        elif operation == "subprocess":
            # A real alternate execution path, with fixed code and no shell.
            child = subprocess.run(
                [sys.executable, "-I", "-B", "-c",
                 "import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(b'UNAUTHORIZED\\n')",
                 path], stdin=subprocess.DEVNULL, capture_output=True, timeout=3, check=False,
            )
            return {"status": "unexpected", "returncode": child.returncode}
        else:
            raise RuntimeError("unknown fixture operation")
    except OSError as exc:
        return {"status": "blocked" if exc.errno in (errno.EACCES, errno.EPERM) else "error",
                "errno": exc.errno}
    return {"status": "unexpected"}


def main() -> int:
    channel = socket.socket(fileno=int(sys.argv[1]))
    channel.settimeout(10)
    try:
        abi = restrict_worker()
    except SandboxUnavailable as exc:
        send_message(channel, {"kind": "unavailable", "reason": str(exc)})
        return 2
    send_message(channel, {"kind": "ready", "landlock_abi": abi, "uid": os.getuid()})
    while True:
        instruction = receive_message(channel)
        if instruction["op"] == "stop":
            return 0
        if instruction["op"] == "broker":
            send_message(channel, {"kind": "broker", "command": instruction["command"]})
            result = receive_message(channel)
        else:
            result = attempt(instruction)
        send_message(channel, {"kind": "result", "result": result})


if __name__ == "__main__":
    raise SystemExit(main())
