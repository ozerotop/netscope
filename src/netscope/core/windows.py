"""Run Windows built-in tools safely, without shell=True."""
from __future__ import annotations
import ctypes
import os
import subprocess


def decode_console(data: bytes) -> str:
    if os.name == "nt":
        try:
            codepage = ctypes.windll.kernel32.GetOEMCP()
            return data.decode(f"cp{codepage}", errors="replace")
        except (AttributeError, LookupError, OSError):
            pass
    return data.decode("utf-8", errors="replace")


def run_windows(args: list[str], timeout: float = 12) -> tuple[int, str]:
    if os.name != "nt":
        raise RuntimeError("Windows-specific check (requires Windows 11)")
    try:
        result = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(f"Command timed out after {timeout}s: {args[0]}") from exc
    return result.returncode, decode_console(result.stdout or b"")
