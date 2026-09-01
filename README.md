# Disk Encryption Status Checker

A dependency-free, read-only Python utility for collecting local disk-encryption status information on:

- **Windows** — BitLocker
- **macOS** — FileVault / APFS encryption information
- **Linux** — LUKS-related block-device information

It is intended for system security auditing, endpoint hardening, compliance checks, and defensive administration.

## Features

- Cross-platform OS detection
- Windows BitLocker status via `manage-bde`
- macOS FileVault status via `fdesetup`
- macOS APFS information via `diskutil`
- Linux block-device information via `lsblk`
- Optional Linux `cryptsetup` status command
- No shell invocation
- Command timeouts
- Graceful handling of unavailable commands
- Human-readable output
- JSON output for automation
- Conservative assessment language
- Unit tests
- GitHub Actions CI
- Python 3.10–3.14
- Standard-library-only

## Requirements

- Python 3.10+
- Supported operating system
- Relevant native OS utilities available

No third-party Python packages are required.

## Usage

Basic:

```bash
python3 disk_encryption_status_checker.py
```

JSON output:

```bash
python3 disk_encryption_status_checker.py --format json
```

Increase the command timeout:

```bash
python3 disk_encryption_status_checker.py --timeout 30
```

## Platform behavior

### Windows

The tool invokes:

```text
manage-bde -status
```

This is the authoritative Windows utility for querying BitLocker volume status.

Depending on the system configuration, administrative privileges may be required to expose some information.

### macOS

The tool invokes:

```text
fdesetup status
diskutil apfs list
```

`fdesetup` provides FileVault status, while `diskutil` provides APFS encryption-related information.

### Linux

The tool invokes:

```text
lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINTS
cryptsetup status
```

The tool looks for `crypto_LUKS` in `lsblk` output as an indication that a LUKS-related encrypted block device is present.

## Important limitation

**Presence of `crypto_LUKS` does not prove that every filesystem or the entire disk is encrypted.**

Modern Linux systems can have:

- encrypted root volumes
- unencrypted boot partitions
- multiple disks with different encryption states
- LVM inside LUKS
- LUKS inside other storage layers
- network-mounted filesystems
- encrypted home directories rather than full-disk encryption

Therefore, this project deliberately reports an **indicator**, not a definitive "full disk encrypted" verdict.

Likewise, platform commands can expose different information depending on OS version, configuration, permissions, and storage architecture.

## Safety

The utility performs local, read-only status checks. It does not:

- enable or disable encryption
- unlock encrypted volumes
- change keys
- modify partitions
- mount filesystems
- alter BitLocker/FileVault/LUKS configuration
- transmit collected output over the network

Use it only on systems you own or are authorized to audit.

## Automation

JSON output is suitable for ingestion into a compliance or endpoint-audit pipeline:

```bash
python3 disk_encryption_status_checker.py --format json > encryption-status.json
```

Before uploading generated reports to a central system, review them for hostnames, mount points, device names, or other environment-specific information.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Supported OS status collection completed |
| `1` | Unsupported OS or no supported platform commands |
| `2` | Argument parsing/usage error |

A return code of `0` means the commands completed; it does **not** mean encryption is necessarily enabled.

## Development

Run tests:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

## License

MIT. See [LICENSE](LICENSE).
