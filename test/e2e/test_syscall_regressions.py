"""Regression tests ensuring basic C programs survive sandbox seccomp rules.

These tests follow the same execution path as the other end-to-end cases:
we invoke the sandbox binary directly (via ``sudo``) and inspect the
result/ stdout/ stderr files it produces.  The only difference is that we
create the source code on the fly so the test suite can guard against
future changes to the syscall whitelist (e.g. missing ``futex`` or
``getrandom``).
"""

from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest


SANDBOX_BIN = Path(__file__).resolve().parents[2] / "sandbox"


def _require_sudo() -> None:
    """Skip the test suite when password-less sudo is unavailable."""

    try:
        subprocess.run(
            ["sudo", "-n", "true"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        pytest.skip("sudo without password is required to run sandbox tests")


def _run_sandbox(
    temp: Path,
    *,
    compile_flag: bool,
    stdin_path: str,
    time_limit: int = 1000,
) -> dict[str, str]:
    stdout_path = temp / "stdout"
    stderr_path = temp / "stderr"
    result_path = temp / "result"
    for path in (stdout_path, stderr_path, result_path):
        if path.exists():
            path.unlink()

    args = [
        "sudo",
        str(SANDBOX_BIN),
        "0",  # lang_id for C
        "1" if compile_flag else "0",
        stdin_path,
        str(stdout_path),
        str(stderr_path),
        str(time_limit),
        "262144",  # memory limit in KB (256 MB)
        "1",  # large stack
        "1073741824",  # output limit (1 GiB)
        "10",  # process limit
        str(result_path),
    ]

    completed = subprocess.run(
        args,
        cwd=temp,
        capture_output=True,
        text=True,
    )

    if completed.returncode != 0:
        raise AssertionError(
            "sandbox execution failed:\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )

    lines = result_path.read_text().splitlines()
    return {
        "status": lines[0] if lines else "",
        "exit_msg": lines[1] if len(lines) > 1 else "",
        "duration": lines[2] if len(lines) > 2 else "",
        "memory": lines[3] if len(lines) > 3 else "",
        "stdout": stdout_path.read_text(),
        "stderr": stderr_path.read_text(),
    }


def _prepare_and_run(source: str, stdin: str = "") -> dict[str, str]:
    _require_sudo()
    with TemporaryDirectory(prefix="sandbox-regression-") as tmp_dir:
        temp = Path(tmp_dir)
        (temp / "main.c").write_text(textwrap.dedent(source))
        input_path = temp / "input"
        input_path.write_text(stdin)

        compile_result = _run_sandbox(
            temp,
            compile_flag=True,
            stdin_path="/dev/null",
        )
        assert compile_result["status"] == "Exited Normally", compile_result
        assert (temp / "main").exists(), "compiled binary not produced"

        run_result = _run_sandbox(
            temp,
            compile_flag=False,
            stdin_path=str(input_path),
        )
        return run_result


def test_plain_stdout_program_exits_normally():
    result = _prepare_and_run(
        """
        #include <stdio.h>

        int main(void) {
            puts("hello world");
            return 0;
        }
        """,
    )
    assert result["status"] == "Exited Normally", result
    assert result["exit_msg"].startswith("WIFEXITED"), result
    assert result["stderr"] == ""


def test_pthread_mutex_program_exits_normally():
    result = _prepare_and_run(
        """
        #include <pthread.h>
        #include <stdio.h>

        int main(void) {
            pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
            pthread_mutex_lock(&lock);
            puts("locked");
            pthread_mutex_unlock(&lock);
            return 0;
        }
        """,
    )
    assert result["status"] == "Exited Normally", result
    assert result["exit_msg"].startswith("WIFEXITED"), result
    assert result["stderr"] == ""
