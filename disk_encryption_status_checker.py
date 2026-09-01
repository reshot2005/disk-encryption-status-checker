#!/usr/bin/env python3
"""Cross-platform disk-encryption status checker.

Collects read-only encryption status information from supported operating
systems. Results are advisory and should be verified against the OS's
authoritative security-management tools.
"""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from typing import Sequence


@dataclass(frozen=True)
class CommandResult:
    command: str
    available: bool
    returncode: int | None
    stdout: str
    stderr: str


def run_command(command: Sequence[str], timeout: float = 15.0) -> CommandResult:
    """Run a local read-only command without invoking a shell."""
    executable = shutil.which(command[0])

    if executable is None:
        return CommandResult(
            command=" ".join(command),
            available=False,
            returncode=None,
            stdout="",
            stderr=f"Command not found: {command[0]}",
        )

    try:
        completed = subprocess.run(
            list(command),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(
            command=" ".join(command),
            available=True,
            returncode=None,
            stdout="",
            stderr=f"Command timed out after {timeout:g} seconds.",
        )
    except OSError as exc:
        return CommandResult(
            command=" ".join(command),
            available=True,
            returncode=None,
            stdout="",
            stderr=str(exc),
        )

    return CommandResult(
        command=" ".join(command),
        available=True,
        returncode=completed.returncode,
        stdout=completed.stdout.strip(),
        stderr=completed.stderr.strip(),
    )


def collect_status(system: str, timeout: float) -> tuple[str, list[CommandResult]]:
    """Collect platform-specific encryption status information."""
    if system == "Windows":
        commands = [
            ("manage-bde", "-status"),
        ]
        platform_name = "Windows / BitLocker"

    elif system == "Darwin":
        commands = [
            ("fdesetup", "status"),
            ("diskutil", "apfs", "list"),
        ]
        platform_name = "macOS / FileVault"

    elif system == "Linux":
        commands = [
            ("lsblk", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINTS"),
            ("cryptsetup", "status"),
        ]
        platform_name = "Linux / LUKS"

    else:
        return system, []

    results = [
        run_command(command, timeout=timeout)
        for command in commands
    ]

    return platform_name, results


def infer_linux_luks(results: list[CommandResult]) -> str:
    """Provide a conservative Linux LUKS indication from lsblk output."""
    for result in results:
        if "crypto_LUKS" in result.stdout:
            return "LUKS-related encrypted block device detected."
    return "No crypto_LUKS entry detected by the available lsblk output."


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Check locally visible disk-encryption status on Windows, "
            "macOS, or Linux."
        )
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        dest="output_format",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="maximum runtime per system command in seconds (default: 15)",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")

    system = platform.system()
    platform_name, results = collect_status(system, args.timeout)

    if not results:
        print(
            f"Unsupported or unrecognized operating system: {system}",
            file=sys.stderr,
        )
        return 1

    if args.output_format == "json":
        payload = {
            "operating_system": system,
            "platform": platform_name,
            "results": [asdict(result) for result in results],
        }
        if system == "Linux":
            payload["assessment"] = infer_linux_luks(results)
        print(json.dumps(payload, indent=2))
        return 0

    print(f"Operating system: {system}")
    print(f"Platform: {platform_name}\n")

    for result in results:
        print(f"$ {result.command}")

        if not result.available:
            print(f"[UNAVAILABLE] {result.stderr}\n")
            continue

        print(f"Return code: {result.returncode}")

        if result.stdout:
            print(result.stdout)

        if result.stderr:
            print(f"\nstderr: {result.stderr}")

        print()

    if system == "Linux":
        print(f"Assessment: {infer_linux_luks(results)}")
        print(
            "Note: an encrypted root/device layout cannot be determined "
            "reliably from FSTYPE alone."
        )

    print(
        "\nThis is an advisory local check; verify the result with your "
        "OS's authoritative encryption-management interface."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
