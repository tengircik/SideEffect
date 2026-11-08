"""Synthetic adversarial tests for the Linux release archive validator."""

from __future__ import annotations

import io
import os
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import smoke_linux_release_archive as validator  # noqa: E402


VERSION = "0.1.0"
TOP = f"sideeffect-v{VERSION}-linux-x86_64"


def make_archive(path: Path, mutation: str | None = None) -> None:
    """Create a synthetic fixture archive; its executable is inert test data."""
    with tarfile.open(path, "w:gz") as archive:
        if mutation not in ("missing-root", "root-file"):
            root = tarfile.TarInfo(f"{TOP}/")
            root.type = tarfile.DIRTYPE
            archive.addfile(root)
        if mutation == "root-file":
            root_file = tarfile.TarInfo(TOP)
            root_file.size = 1
            archive.addfile(root_file, io.BytesIO(b"x"))
        files = {name: b"synthetic fixture\n" for name in validator.EXPECTED_FILES}
        files["sideeffect"] = b"synthetic non-executable CLI fixture\n"
        if mutation == "unexpected":
            files.pop("RELEASE_NOTES.md")
        if mutation == "oversized":
            files["README.md"] = b"x" * (validator.FILE_LIMITS["README.md"] + 1)
        for name, contents in files.items():
            member = tarfile.TarInfo(f"{TOP}/{name}")
            member.size = len(contents)
            member.mode = 0o755 if name == "sideeffect" else 0o644
            archive.addfile(member, io.BytesIO(contents))

        if mutation == "traversal":
            member = tarfile.TarInfo(f"{TOP}/../outside")
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
        elif mutation == "absolute":
            member = tarfile.TarInfo("/tmp/outside")
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
        elif mutation == "link":
            member = tarfile.TarInfo(f"{TOP}/evil-link")
            member.type = tarfile.SYMTYPE
            member.linkname = "../../outside"
            archive.addfile(member)
        elif mutation == "duplicate":
            member = tarfile.TarInfo(f"{TOP}/README.md")
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
        elif mutation == "unexpected":
            member = tarfile.TarInfo(f"{TOP}/extra.txt")
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))


class LinuxReleaseArchiveSmokeTests(unittest.TestCase):
    def test_valid_synthetic_archive_is_safely_inspected_and_cli_checked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "fixture.tar.gz"
            make_archive(archive)
            with mock.patch.object(
                validator,
                "_run_cli",
                side_effect=["SideEffect test help", f"sideeffect {VERSION}\n"],
            ) as run_cli:
                validator.smoke_archive(archive, VERSION, root)
            self.assertEqual(
                [call.args[1] for call in run_cli.call_args_list], [["--help"], ["version"]]
            )
            self.assertTrue(archive.exists())

    def test_rejects_adversarial_archive_members_before_cli_execution(self) -> None:
        for mutation in (
            "traversal",
            "absolute",
            "link",
            "duplicate",
            "unexpected",
            "oversized",
            "missing-root",
            "root-file",
        ):
            with self.subTest(member=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / "fixture.tar.gz"
                make_archive(archive, mutation)
                with mock.patch.object(validator, "_run_cli") as run_cli:
                    if mutation == "duplicate":
                        expected_message = "duplicate archive member"
                    elif mutation == "oversized":
                        expected_message = "exceeds its .*byte limit"
                    elif mutation == "missing-root":
                        expected_message = "missing its exact top-level directory"
                    else:
                        expected_message = ""
                    with self.assertRaisesRegex(validator.ArchiveError, expected_message):
                        validator.smoke_archive(archive, VERSION, root)
                run_cli.assert_not_called()
                self.assertFalse((root / "outside").exists())

    def test_rejects_wrong_release_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "fixture.tar.gz"
            make_archive(archive)
            with self.assertRaises(validator.ArchiveError):
                validator.smoke_archive(archive, "0.1.1", root)

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "fork"), "requires POSIX process groups")
    def test_timeout_kills_descendant_after_cli_leader_exits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pid_file = root / "descendant.pid"
            executable = root / "synthetic-cli"
            executable.write_text(
                f"#!{sys.executable}\n"
                "import os, time\n"
                f"pid_file = {str(pid_file)!r}\n"
                "child = os.fork()\n"
                "if child == 0:\n"
                "    with open(pid_file, 'w', encoding='ascii') as stream:\n"
                "        stream.write(f'{os.getpid()} {os.getpgrp()}')\n"
                "    time.sleep(30)\n"
                "    os._exit(0)\n"
                "os._exit(0)\n",
                encoding="utf-8",
            )
            executable.chmod(0o755)

            def recorded_process() -> tuple[int, int] | None:
                try:
                    child, process_group = pid_file.read_text(encoding="ascii").split()
                    return int(child), int(process_group)
                except (FileNotFoundError, ValueError):
                    return None

            with mock.patch.object(validator, "COMMAND_TIMEOUT_SECONDS", 0.2):
                with mock.patch.object(validator.os, "killpg", wraps=os.killpg) as kill_group:
                    with self.assertRaisesRegex(validator.ArchiveError, "timed out"):
                        validator._run_cli(executable, ["--help"])
            recorded = recorded_process()
            self.assertIsNotNone(recorded, "synthetic descendant did not start")
            child_pid, process_group = recorded
            kill_group.assert_called_once_with(process_group, validator.signal.SIGKILL)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    process_state = Path(f"/proc/{child_pid}/stat").read_text().split()[2]
                except FileNotFoundError:
                    break
                if process_state == "Z":
                    break
                time.sleep(0.05)
            else:
                self.fail("timed-out CLI descendant remained alive after process-group cleanup")


if __name__ == "__main__":
    unittest.main()
