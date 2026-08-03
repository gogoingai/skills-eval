"""Bounded subprocess execution and scan-input staging shared by security providers.

Every external scanner adapter funnels its CLI invocation through :func:`run_subprocess`
so that timeout handling, output bounding, and process-group cleanup stay consistent.
Scan inputs are staged through :func:`staged_scan_input` so repository-ignored files
(``.gitignore``) never reach an external tool.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from threading import Lock, Thread
from typing import Any

import pathspec

_PROCESS_OUTPUT_LIMIT = 64 * 1024
_READ_CHUNK_SIZE = 8 * 1024
_CAPTURE_JOIN_TIMEOUT_SECONDS = 0.25
_PROCESS_TERMINATION_TIMEOUT_SECONDS = 1.0


def run_subprocess(
    args: list[str],
    *,
    timeout: float,
    env: dict[str, str] | None = None,
    cwd: str | Path | None = None,
    stdout_limit: int = _PROCESS_OUTPUT_LIMIT,
    stderr_limit: int = _PROCESS_OUTPUT_LIMIT,
) -> tuple[int, str, str]:
    """Run *args* with bounded execution and captured output.

    Always uses an argument array (never ``shell=True``), starts a new process
    group so descendants can be killed on timeout, and bounds ``stdout``/``stderr``
    to *stdout_limit*/*stderr_limit* bytes. Raises :class:`subprocess.TimeoutExpired`
    on timeout, :class:`FileNotFoundError` when the executable is missing, and
    :class:`OSError` for other launch failures.
    """
    process = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=cwd,
        **_process_group_options(),
    )
    assert process.stdout is not None
    assert process.stderr is not None

    stdout_capture = _BoundedStreamCapture(stdout_limit)
    stderr_capture = _BoundedStreamCapture(stderr_limit)
    stdout_thread = Thread(target=stdout_capture.drain, args=(process.stdout,), daemon=True)
    stderr_thread = Thread(target=stderr_capture.drain, args=(process.stderr,), daemon=True)
    try:
        stdout_thread.start()
        stderr_thread.start()

        timed_out = False
        try:
            return_code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate_process_group(process)
            return_code = _wait_for_process(process)

        captures_complete = _join_capture_threads(stdout_thread, stderr_thread)
        if not captures_complete:
            timed_out = True
            _terminate_process_group(process)
            return_code = _wait_for_process(process)
            _join_capture_threads(stdout_thread, stderr_thread)

        stdout = stdout_capture.text()
        stderr = stderr_capture.text()
        if timed_out:
            raise subprocess.TimeoutExpired(
                cmd=args, timeout=timeout, output=stdout, stderr=stderr
            )
        return return_code, stdout, stderr
    except subprocess.TimeoutExpired:
        raise
    except BaseException:
        _terminate_process_group(process)
        _wait_for_process(process)
        _join_capture_threads(stdout_thread, stderr_thread)
        raise


def resolve_executable(name: str) -> str:
    """Resolve *name* to an executable, preferring PATH then the venv bin directory.

    pipx and uv tool environments install dependency entry points in their own
    ``bin`` directory but do not always expose that directory to child-process
    ``PATH`` lookups.
    """
    if shutil.which(name) is not None:
        return name
    bundled = Path(sys.executable).parent / name
    return str(bundled) if bundled.is_file() else name


def executable_path(name: str) -> Path | None:
    """Return the existing executable path (PATH or venv bin) or ``None``."""
    found = shutil.which(name)
    if found:
        return Path(found)
    bundled = Path(sys.executable).parent / name
    if bundled.is_file():
        return bundled
    return None


@contextmanager
def staged_scan_input(skill_path: Path) -> Iterator[Path]:
    """Yield a scan directory excluding the nearest repository's ignored paths.

    When the skill lives below a ``.gitignore`` root, a temporary copy is made
    with ignored entries removed so scanners never see build artifacts, caches,
    or secrets that git already ignores. With no ignore root the skill path is
    yielded directly.
    """
    ignore_root = _find_gitignore_root(skill_path)
    if ignore_root is None:
        yield skill_path
        return

    lines = (ignore_root / ".gitignore").read_text(encoding="utf-8").splitlines()
    spec = pathspec.GitIgnoreSpec.from_lines(lines)
    with tempfile.TemporaryDirectory(prefix="skills-eval-scan-input-") as directory:
        staged_path = Path(directory) / "skill"
        shutil.copytree(
            skill_path,
            staged_path,
            symlinks=True,
            ignore=_gitignore_copy_filter(ignore_root, spec),
        )
        yield staged_path


def _find_gitignore_root(path: Path) -> Path | None:
    for candidate in (path, *path.parents):
        if (candidate / ".gitignore").is_file():
            return candidate
    return None


def _gitignore_copy_filter(
    root: Path, spec: pathspec.GitIgnoreSpec
) -> Callable[[str, list[str]], set[str]]:
    def ignored_names(directory: str, names: list[str]) -> set[str]:
        relative_directory = Path(directory).resolve().relative_to(root.resolve())
        ignored: set[str] = set()
        for name in names:
            candidate = Path(directory) / name
            relative_path = (relative_directory / name).as_posix()
            if candidate.is_dir():
                relative_path += "/"
            if spec.match_file(relative_path):
                ignored.add(name)
        return ignored

    return ignored_names


class _BoundedStreamCapture:
    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._contents = bytearray()
        self._truncated = False
        self._lock = Lock()

    def drain(self, stream: Any) -> None:
        try:
            while chunk := stream.read(_READ_CHUNK_SIZE):
                with self._lock:
                    remaining = self._limit - len(self._contents)
                    if remaining > 0:
                        self._contents.extend(chunk[:remaining])
                    if len(chunk) > max(remaining, 0):
                        self._truncated = True
        finally:
            stream.close()

    def text(self) -> str:
        with self._lock:
            contents = bytes(self._contents)
            truncated = self._truncated
        text = contents.decode("utf-8", errors="replace")
        if truncated:
            return f"{text}\n[truncated]"
        return text


def _process_group_options() -> dict[str, object]:
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=_PROCESS_TERMINATION_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            pass
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

    if process.poll() is None:
        try:
            process.kill()
        except ProcessLookupError:
            pass


def _wait_for_process(process: subprocess.Popen[bytes]) -> int:
    try:
        return process.wait(timeout=_PROCESS_TERMINATION_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        try:
            return process.wait(timeout=_PROCESS_TERMINATION_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            return process.returncode if process.returncode is not None else -1


def _join_capture_threads(*threads: Thread) -> bool:
    for thread in threads:
        if thread.ident is not None:
            thread.join(timeout=_CAPTURE_JOIN_TIMEOUT_SECONDS)
    return all(thread.ident is None or not thread.is_alive() for thread in threads)
