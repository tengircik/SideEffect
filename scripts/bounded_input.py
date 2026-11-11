"""Read evaluator inputs without reopening a validated pathname."""

from __future__ import annotations

import errno
import os
import stat
from pathlib import Path


def open_regular_file(path: Path) -> int:
    """Open the final component without following links or waiting on a FIFO."""
    if os.name == "nt":
        fd = _open_windows_disk_file(path)
    elif hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_NONBLOCK"):
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError as error:
            if error.errno == errno.ELOOP:
                raise ValueError("must be a regular non-symlink file") from None
            raise
    else:
        raise OSError("safe regular-file input is unavailable on this platform")

    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("must be a regular non-symlink file")
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_regular_file(path: Path, limit: int, label: str) -> bytes:
    try:
        fd = open_regular_file(path)
    except ValueError as error:
        raise ValueError(f"{label} {error}") from None

    with os.fdopen(fd, "rb") as source:
        if os.fstat(source.fileno()).st_size > limit:
            raise ValueError(f"{label} exceeds its byte limit of {limit} bytes")
        raw = source.read(limit + 1)
    if len(raw) > limit:
        raise ValueError(f"{label} grew beyond its byte limit of {limit} bytes")
    return raw


def _open_windows_disk_file(path: Path) -> int:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class FileAttributeTagInfo(ctypes.Structure):
        _fields_ = [("attributes", wintypes.DWORD), ("reparse_tag", wintypes.DWORD)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.GetFileType.argtypes = [wintypes.HANDLE]
    kernel.GetFileType.restype = wintypes.DWORD
    kernel.GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
    ]
    kernel.GetFileInformationByHandleEx.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL

    handle = kernel.CreateFileW(
        os.fspath(path), 0x80000000, 1, None, 3, 0x00200000, None,
        # GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT
    )
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if kernel.GetFileType(handle) != 1:  # FILE_TYPE_DISK
            raise ValueError("must be a regular non-symlink file")
        info = FileAttributeTagInfo()
        if not kernel.GetFileInformationByHandleEx(handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        if info.attributes & 0x410:  # FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY
            raise ValueError("must be a regular non-symlink file")
        return msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY | os.O_NOINHERIT)
    except BaseException:
        kernel.CloseHandle(handle)
        raise
