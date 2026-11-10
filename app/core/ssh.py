"""System SSH discovery, key parsing, auditing and key generation.

The module deliberately has no GUI dependencies so it can be exercised from
tests and from a terminal.
"""

from __future__ import annotations

import base64
import binascii
import getpass
import glob
import hashlib
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

try:  # cryptography is optional for reading legacy PEM keys and generating keys
    from cryptography.hazmat.primitives import serialization as _serialization
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
except Exception:  # pragma: no cover - optional dependency
    _serialization = None
    _ec = None
    _ed25519 = None
    _rsa = None


# ---------------------------------------------------------------------------
# Binary helpers


class SSHFormatError(ValueError):
    """Raised when an SSH blob is malformed."""


def _read_uint32(data: bytes, pos: int) -> tuple[int, int]:
    if pos + 4 > len(data):
        raise SSHFormatError("truncated uint32")
    return int.from_bytes(data[pos : pos + 4], "big"), pos + 4


def _read_uint64(data: bytes, pos: int) -> tuple[int, int]:
    if pos + 8 > len(data):
        raise SSHFormatError("truncated uint64")
    return int.from_bytes(data[pos : pos + 8], "big"), pos + 8


def _read_string(data: bytes, pos: int) -> tuple[bytes, int]:
    length, pos = _read_uint32(data, pos)
    if pos + length > len(data):
        raise SSHFormatError("truncated string")
    return data[pos : pos + length], pos + length


def _read_mpint(data: bytes, pos: int) -> tuple[int, int]:
    raw, pos = _read_string(data, pos)
    return int.from_bytes(raw, "big", signed=False), pos


def _looks_like_key_type(value: str) -> bool:
    return value.startswith(("ssh-", "ecdsa-", "sk-")) and " " not in value


def _key_bits(key_type: str, blob: bytes) -> int | None:
    """Return the cryptographic size of the public key, when knowable."""

    try:
        embedded_type, pos = _read_string(blob, 0)
        embedded_type_text = embedded_type.decode("ascii", "replace")
        if embedded_type_text.endswith("-cert-v01@openssh.com"):
            # Certificates start with a nonce, then the certified public key.
            _nonce, pos = _read_string(blob, pos)
            certified, pos = _read_string(blob, pos)
            return _key_bits(embedded_type_text.replace("-cert-v01@openssh.com", ""), certified)

        if embedded_type_text == "ssh-rsa":
            _e, pos = _read_mpint(blob, pos)
            n, pos = _read_mpint(blob, pos)
            return n.bit_length()
        if embedded_type_text == "ssh-dss":
            p, pos = _read_mpint(blob, pos)
            return p.bit_length()
        if embedded_type_text.startswith("ecdsa-sha2-"):
            curve, pos = _read_string(blob, pos)
            sizes = {"nistp256": 256, "nistp384": 384, "nistp521": 521}
            return sizes.get(curve.decode("ascii", "replace"))
        if embedded_type_text.startswith("sk-ecdsa-sha2-nistp256"):
            return 256
        if embedded_type_text in ("ssh-ed25519", "sk-ssh-ed25519@openssh.com"):
            return 256
    except (SSHFormatError, UnicodeDecodeError):
        pass

    if key_type.startswith("ecdsa-sha2-nistp"):
        match = re.search(r"nistp(\d+)", key_type)
        if match:
            return int(match.group(1))
    return None


@dataclass(slots=True)
class PublicKeyData:
    key_type: str
    blob: bytes
    fingerprint: str
    fingerprint_md5: str
    bits: int | None
    comment: str = ""
    options: str = ""

    @property
    def base64_body(self) -> str:
        return base64.b64encode(self.blob).decode("ascii")

    @property
    def line(self) -> str:
        suffix = f" {self.comment}" if self.comment else ""
        return f"{self.key_type} {self.base64_body}{suffix}"


def parse_public_key_line(line: str) -> PublicKeyData | None:
    """Parse an OpenSSH one-line public key.

    Works for regular public key files, authorized_keys (with leading
    options), known_hosts (after the host field is removed) and certificates.
    """

    text = line.strip()
    if not text or text.startswith("#"):
        return None
    if text.startswith("@"):  # known_hosts marker
        _, _, text = text.partition(" ")
        text = text.strip()

    token_iter = list(re.finditer(r"\S+", text))
    for index in range(1, len(token_iter)):
        token = token_iter[index]
        try:
            blob = base64.b64decode(token.group(), validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(blob) < 12:
            continue
        try:
            raw_type, _ = _read_string(blob, 0)
            key_type = raw_type.decode("ascii")
        except (SSHFormatError, UnicodeDecodeError):
            continue
        if not _looks_like_key_type(key_type):
            continue

        type_start = token_iter[index - 1].start()
        options = text[:type_start].strip() if index > 1 else ""
        comment = text[token.end() :].strip()
        digest = hashlib.sha256(blob).digest()
        md5 = hashlib.md5(blob).hexdigest()
        return PublicKeyData(
            key_type=key_type,
            blob=blob,
            fingerprint="SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("="),
            fingerprint_md5="MD5:" + ":".join(md5[i : i + 2] for i in range(0, 32, 2)),
            bits=_key_bits(key_type, blob),
            comment=comment,
            options=options,
        )
    return None


# ---------------------------------------------------------------------------
# Data model


@dataclass(slots=True)
class AgentKey:
    bits: int | None
    fingerprint: str
    comment: str
    key_type: str


@dataclass(slots=True)
class AgentStatus:
    available: bool = False
    running: bool = False
    keys: list[AgentKey] = field(default_factory=list)
    message: str = ""


@dataclass(slots=True)
class CertificateInfo:
    path: str
    key_type: str
    fingerprint: str
    key_id: str = ""
    principals: list[str] = field(default_factory=list)
    valid_after: int = 0
    valid_before: int = 0
    expired: bool = False
    not_yet_valid: bool = False


@dataclass(slots=True)
class KeyRecord:
    name: str
    private_path: str | None = None
    public_path: str | None = None
    key_type: str = ""
    bits: int | None = None
    fingerprint: str = ""
    fingerprint_md5: str = ""
    comment: str = ""
    public_key: str = ""
    encrypted: bool | None = None
    has_private: bool = False
    has_public: bool = False
    reconstructed_public: bool = False
    pair_mismatch: bool = False
    modified: datetime | None = None
    size: int = 0
    permission_warning: str | None = None
    certificate: CertificateInfo | None = None
    source: str = ""

    @property
    def display_type(self) -> str:
        names = {
            "ssh-ed25519": "ED25519",
            "ssh-rsa": "RSA",
            "ssh-dss": "DSA",
            "ecdsa-sha2-nistp256": "ECDSA P-256",
            "ecdsa-sha2-nistp384": "ECDSA P-384",
            "ecdsa-sha2-nistp521": "ECDSA P-521",
            "sk-ssh-ed25519@openssh.com": "ED25519-SK",
            "sk-ecdsa-sha2-nistp256@openssh.com": "ECDSA-SK",
        }
        base = self.key_type.replace("-cert-v01@openssh.com", "")
        if base in names:
            return names[base]
        return base.upper() if base else "未知"

    @property
    def location(self) -> str:
        return self.private_path or self.public_path or ""


@dataclass(slots=True)
class KnownHostEntry:
    hosts: list[str]
    key_type: str
    fingerprint: str
    line: int
    marker: str = ""
    hashed: bool = False
    source: str = ""
    bits: int | None = None

    @property
    def host_label(self) -> str:
        if not self.hosts:
            return "—"
        label = self.hosts[0]
        if len(self.hosts) > 1:
            label += f" +{len(self.hosts) - 1}"
        return label

    @property
    def is_revoked(self) -> bool:
        return self.marker == "@revoked"

    @property
    def is_ca(self) -> bool:
        return self.marker == "@cert-authority"


@dataclass(slots=True)
class AuthorizedKeyEntry:
    key_type: str
    fingerprint: str
    bits: int | None
    comment: str
    options: str
    line: int
    source: str

    @property
    def source_name(self) -> str:
        return Path(self.source).name

    @property
    def is_restricted(self) -> bool:
        return bool(self.options.strip())


@dataclass(slots=True)
class HostConfig:
    alias: str
    hostname: str = ""
    user: str = ""
    port: str = ""
    identity_files: list[str] = field(default_factory=list)
    proxy_jump: str = ""
    options: dict[str, str] = field(default_factory=dict)
    source: str = ""
    line: int = 0
    is_pattern: bool = False

    @property
    def endpoint(self) -> str:
        host = self.hostname or self.alias
        if self.port:
            host = f"{host}:{self.port}"
        return host


@dataclass(slots=True)
class Finding:
    severity: str  # critical | warning | info
    title: str
    detail: str
    remediation: str = ""
    category: str = ""


@dataclass(slots=True)
class ServerInfo:
    installed: bool = False
    running: bool = False
    state: str = "未安装"
    config_path: str = ""
    host_keys: list[PublicKeyData] = field(default_factory=list)
    password_auth: bool | None = None
    permit_root: str = ""
    pubkey_auth: bool | None = None


@dataclass(slots=True)
class ScanResult:
    ssh_dir: str
    exists: bool = False
    keys: list[KeyRecord] = field(default_factory=list)
    known_hosts: list[KnownHostEntry] = field(default_factory=list)
    known_hosts_old_count: int = 0
    hosts: list[HostConfig] = field(default_factory=list)
    agent: AgentStatus = field(default_factory=AgentStatus)
    server: ServerInfo = field(default_factory=ServerInfo)
    ssh_version: str = ""
    ssh_path: str = ""
    keygen_path: str = ""
    ssh_add_path: str = ""
    findings: list[Finding] = field(default_factory=list)
    score: int = 100
    grade: str = "优秀"
    raw_configs: dict[str, str] = field(default_factory=dict)
    config_files: list[str] = field(default_factory=list)
    authorized_keys: list[AuthorizedKeyEntry] = field(default_factory=list)
    authorized_keys_count: int = 0
    certificates: int = 0
    directory_warning: str | None = None
    scanned_at: datetime = field(default_factory=lambda: datetime.now())
    errors: list[str] = field(default_factory=list)
    total_files: int = 0

    @property
    def private_count(self) -> int:
        return sum(1 for key in self.keys if key.has_private)

    @property
    def public_count(self) -> int:
        return sum(1 for key in self.keys if key.has_public or key.reconstructed_public)

    @property
    def encrypted_count(self) -> int:
        return sum(1 for key in self.keys if key.has_private and key.encrypted)

    @property
    def host_count(self) -> int:
        return len({host.alias for host in self.hosts if not host.is_pattern})

    @property
    def unique_known_hosts(self) -> int:
        hosts: set[str] = set()
        for entry in self.known_hosts:
            for host in entry.hosts:
                hosts.add(host)
        return len(hosts)

    @property
    def counts_by_severity(self) -> dict[str, int]:
        counts = {"critical": 0, "warning": 0, "info": 0}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts


# ---------------------------------------------------------------------------
# Parsing private keys and certificate blobs


@dataclass(slots=True)
class PrivateKeyData:
    key_type: str
    blob: bytes
    bits: int | None
    encrypted: bool


_OPENSSH_HEADER = "-----BEGIN OPENSSH PRIVATE KEY-----"
_OPENSSH_FOOTER = "-----END OPENSSH PRIVATE KEY-----"


def _parse_openssh_private(data: bytes) -> PrivateKeyData:
    text = data.decode("utf-8", "ignore")
    if _OPENSSH_HEADER not in text or _OPENSSH_FOOTER not in text:
        raise SSHFormatError("not an OpenSSH private key")
    body = text.split(_OPENSSH_HEADER, 1)[1].split(_OPENSSH_FOOTER, 1)[0]
    raw = base64.b64decode("".join(body.split()), validate=True)
    magic = b"openssh-key-v1\x00"
    if not raw.startswith(magic):
        raise SSHFormatError("bad OpenSSH key magic")
    pos = len(magic)
    cipher, pos = _read_string(raw, pos)
    kdf, pos = _read_string(raw, pos)
    kdf_options, pos = _read_string(raw, pos)
    key_count, pos = _read_uint32(raw, pos)
    if key_count < 1:
        raise SSHFormatError("no public key in private key file")
    blob, pos = _read_string(raw, pos)
    key_type_raw, _ = _read_string(blob, 0)
    key_type = key_type_raw.decode("ascii", "replace")
    return PrivateKeyData(
        key_type=key_type,
        blob=blob,
        bits=_key_bits(key_type, blob),
        encrypted=cipher not in (b"none", b""),
    )


def _parse_pem_private(data: bytes) -> PrivateKeyData:
    text = data.decode("utf-8", "ignore")
    encrypted = "ENCRYPTED PRIVATE KEY" in text or "Proc-Type: 4,ENCRYPTED" in text
    if _serialization is not None and not encrypted:
        try:
            key = _serialization.load_pem_private_key(data, password=None)
            public = key.public_key().public_bytes(
                _serialization.Encoding.OpenSSH,
                _serialization.PublicFormat.OpenSSH,
            )
            parsed = parse_public_key_line(public.decode("ascii"))
            if parsed:
                return PrivateKeyData(parsed.key_type, parsed.blob, parsed.bits, False)
        except Exception:
            pass

    types = [
        ("RSA PRIVATE KEY", "ssh-rsa"),
        ("DSA PRIVATE KEY", "ssh-dss"),
        ("EC PRIVATE KEY", "ecdsa-sha2-nistp256"),
        ("PRIVATE KEY", "ssh-rsa"),
    ]
    for marker, key_type in types:
        if marker in text:
            return PrivateKeyData(key_type, b"", None, encrypted)
    raise SSHFormatError("unsupported private key format")


def read_private_key(path: Path) -> PrivateKeyData:
    data = path.read_bytes()
    if _OPENSSH_HEADER.encode() in data:
        return _parse_openssh_private(data)
    return _parse_pem_private(data)


def parse_certificate(blob: bytes, path: str = "") -> CertificateInfo | None:
    """Parse the public fields of an OpenSSH certificate blob."""

    try:
        key_type_raw, pos = _read_string(blob, 0)
        key_type = key_type_raw.decode("ascii")
        if not key_type.endswith("-cert-v01@openssh.com"):
            return None
        _nonce, pos = _read_string(blob, pos)
        _certified, pos = _read_string(blob, pos)
        _serial, pos = _read_uint64(blob, pos)
        _cert_type, pos = _read_uint32(blob, pos)
        key_id_raw, pos = _read_string(blob, pos)
        principals_raw, pos = _read_string(blob, pos)
        valid_after, pos = _read_uint64(blob, pos)
        valid_before, pos = _read_uint64(blob, pos)
        principals = [
            item.decode("utf-8", "replace")
            for item in principals_raw.split(b",")
            if item
        ]
        now = int(datetime.now(tz=timezone.utc).timestamp())
        expired = valid_before not in (0, 0xFFFFFFFFFFFFFFFF) and valid_before < now
        not_yet = valid_after > now + 300
        digest = hashlib.sha256(blob).digest()
        return CertificateInfo(
            path=path,
            key_type=key_type,
            fingerprint="SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("="),
            key_id=key_id_raw.decode("utf-8", "replace"),
            principals=principals,
            valid_after=valid_after,
            valid_before=valid_before,
            expired=expired,
            not_yet_valid=not_yet,
        )
    except (SSHFormatError, UnicodeDecodeError):
        return None


# ---------------------------------------------------------------------------
# Small process / filesystem helpers


def _run(
    args: list[str],
    timeout: float = 8.0,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    kwargs: dict[str, Any] = {
        "capture_output": True,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
        "timeout": timeout,
        "env": env,
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.run(args, **kwargs)


def _find_tool(name: str) -> str:
    found = shutil.which(name)
    if found:
        return found
    if os.name == "nt":
        candidate = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "OpenSSH" / f"{name}.exe"
        if candidate.exists():
            return str(candidate)
    return ""


def _read_text(path: Path, limit: int = 512_000) -> str:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return handle.read(limit).lstrip("\ufeff")


def _format_time(timestamp: float) -> datetime:
    return datetime.fromtimestamp(timestamp)


def _windows_acl_issue(path: Path) -> str | None:
    """Return a description when a private file grants access too broadly."""

    if os.name != "nt":
        try:
            mode = path.stat().st_mode
            if mode & 0o077:
                return "文件对其他用户可读"
        except OSError:
            return None
        return None

    icacls = shutil.which("icacls") or str(Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "icacls.exe")
    try:
        proc = _run([icacls, str(path)], timeout=6)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None

    broad = re.compile(
        r"(Everyone|BUILTIN\\Users|Authenticated Users|NT AUTHORITY\\Authenticated Users|"
        r"S-1-1-0|S-1-5-11|S-1-5-32-545)[^:\r\n]*:((?:\([^)]+\))+)",
        re.IGNORECASE,
    )
    for line in proc.stdout.splitlines():
        match = broad.search(line)
        if not match:
            continue
        rights = match.group(2).upper()
        if any(code in rights for code in ("(F)", "(M)", "(W)", "(R)", "(RX)")):
            return f"{match.group(1)} 拥有访问权限"
    return None


def _harden_private_key(path: Path) -> None:
    if os.name != "nt":
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return

    icacls = shutil.which("icacls") or str(Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "icacls.exe")
    user = os.environ.get("USERNAME") or getpass.getuser()
    domain = os.environ.get("USERDOMAIN", "")
    principal = f"{domain}\\{user}" if domain else user
    try:
        _run(
            [
                icacls,
                str(path),
                "/inheritance:r",
                "/grant:r",
                f"{principal}:(F)",
                "/grant:r",
                "*S-1-5-18:(F)",
                "/grant:r",
                "*S-1-5-32-544:(F)",
            ],
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        pass


# ---------------------------------------------------------------------------
# Discovery


def default_ssh_dir() -> Path:
    return Path.home() / ".ssh"


def _system_ssh_dir() -> Path:
    if os.name == "nt":
        return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "ssh"
    return Path("/etc/ssh")


def _system_client_config() -> Path:
    if os.name == "nt":
        return _system_ssh_dir() / "ssh_config"
    return Path("/etc/ssh/ssh_config")


def detect_ssh_version(ssh_path: str) -> str:
    if not ssh_path:
        return "未检测到 OpenSSH"
    try:
        proc = _run([ssh_path, "-V"], timeout=5)
    except (OSError, subprocess.SubprocessError):
        return "OpenSSH（版本未知）"
    text = (proc.stderr or proc.stdout or "").strip().splitlines()
    if not text:
        return "OpenSSH（版本未知）"
    line = text[0].replace("OpenSSH_for_Windows_", "OpenSSH for Windows ")
    return line


def _scan_keys(ssh_dir: Path, errors: list[str]) -> tuple[list[KeyRecord], int, int]:
    records: list[KeyRecord] = []
    if not ssh_dir.is_dir():
        return records, 0, 0

    try:
        entries = sorted(ssh_dir.iterdir(), key=lambda item: item.name.lower())
    except OSError as exc:
        errors.append(f"无法读取 {ssh_dir}: {exc}")
        return records, 0, 0

    file_entries = [entry for entry in entries if entry.is_file()]
    by_stem: dict[str, KeyRecord] = {}
    cert_count = 0

    # First pass: private keys.
    for entry in file_entries:
        if entry.name.endswith((".pub", ".ppk")) or entry.name in ("config", "known_hosts", "authorized_keys"):
            continue
        try:
            head = entry.read_bytes()[:256]
        except OSError:
            continue
        if b"PRIVATE KEY-----" not in head:
            continue

        record = KeyRecord(name=entry.stem, private_path=str(entry), has_private=True, source="私钥文件")
        try:
            parsed = read_private_key(entry)
            record.key_type = parsed.key_type
            record.bits = parsed.bits
            record.encrypted = parsed.encrypted
            if parsed.blob:
                digest = hashlib.sha256(parsed.blob).digest()
                record.fingerprint = "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")
                md5 = hashlib.md5(parsed.blob).hexdigest()
                record.fingerprint_md5 = "MD5:" + ":".join(md5[i : i + 2] for i in range(0, 32, 2))
                record.public_key = f"{parsed.key_type} {base64.b64encode(parsed.blob).decode('ascii')}"
        except (OSError, SSHFormatError, ValueError) as exc:
            record.encrypted = True if "ENCRYPTED" in str(exc).upper() else None
            record.source = "无法解析"

        try:
            stat = entry.stat()
            record.modified = _format_time(stat.st_mtime)
            record.size = stat.st_size
        except OSError:
            pass
        record.permission_warning = _windows_acl_issue(entry)
        by_stem[entry.stem] = record
        records.append(record)

    # Second pass: public keys, merging with private counterparts.
    for entry in file_entries:
        if not entry.name.endswith(".pub"):
            continue
        stem = entry.name[:-4]
        if stem.endswith("-cert"):
            cert_count += 1
            base_stem = stem[:-5]
            record = by_stem.get(base_stem)
            if record is None:
                continue
            try:
                parsed = parse_public_key_line(_read_text(entry))
                if parsed:
                    cert = parse_certificate(parsed.blob, str(entry))
                    record.certificate = cert
            except OSError:
                pass
            continue

        try:
            public_text = _read_text(entry).strip()
            parsed = parse_public_key_line(public_text)
        except OSError as exc:
            errors.append(f"无法读取公钥 {entry.name}: {exc}")
            continue
        if parsed is None:
            continue

        record = by_stem.get(stem)
        if record is None:
            record = KeyRecord(
                name=stem,
                public_path=str(entry),
                has_public=True,
                key_type=parsed.key_type,
                bits=parsed.bits,
                fingerprint=parsed.fingerprint,
                fingerprint_md5=parsed.fingerprint_md5,
                comment=parsed.comment,
                public_key=parsed.line,
                source="仅公钥",
            )
            try:
                stat = entry.stat()
                record.modified = _format_time(stat.st_mtime)
                record.size = stat.st_size
            except OSError:
                pass
            by_stem[stem] = record
            records.append(record)
        else:
            record.public_path = str(entry)
            record.has_public = True
            record.comment = parsed.comment or record.comment
            record.public_key = parsed.line
            if record.fingerprint and parsed.fingerprint != record.fingerprint:
                record.pair_mismatch = True
            if not record.fingerprint:
                record.fingerprint = parsed.fingerprint
                record.fingerprint_md5 = parsed.fingerprint_md5
                record.key_type = parsed.key_type
                record.bits = parsed.bits
            elif not record.key_type:
                record.key_type = parsed.key_type
                record.bits = parsed.bits

    # Attach certificate metadata where the private key was found after its .pub.
    for record in records:
        if record.certificate is None:
            cert_path = Path(record.public_path or "").with_name((Path(record.public_path).stem if record.public_path else record.name) + "-cert.pub") if record.public_path else None
            if cert_path and cert_path.exists():
                try:
                    parsed = parse_public_key_line(_read_text(cert_path))
                    if parsed:
                        record.certificate = parse_certificate(parsed.blob, str(cert_path))
                except OSError:
                    pass

    # Mark private keys whose .pub was reconstructed from the private key.
    for record in records:
        if record.has_private and not record.has_public and record.public_key:
            record.reconstructed_public = True

    records.sort(key=lambda item: (not item.has_private, item.name.lower()))
    return records, cert_count, len(file_entries)


def _parse_known_hosts(path: Path, errors: list[str]) -> list[KnownHostEntry]:
    entries: list[KnownHostEntry] = []
    if not path.exists():
        return entries
    try:
        text = _read_text(path)
    except OSError as exc:
        errors.append(f"无法读取 known_hosts: {exc}")
        return entries

    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        marker = ""
        if stripped.startswith("@"):
            marker, _, stripped = stripped.partition(" ")
            stripped = stripped.strip()
        parts = stripped.split(None, 1)
        if len(parts) != 2:
            continue
        host_field, key_part = parts
        try:
            parsed = parse_public_key_line(key_part)
        except Exception:
            parsed = None
        if parsed is None:
            continue
        hosts = [item for item in host_field.split(",") if item]
        entries.append(
            KnownHostEntry(
                hosts=hosts,
                key_type=parsed.key_type,
                fingerprint=parsed.fingerprint,
                line=number,
                marker=marker,
                hashed=host_field.startswith("|1|"),
                source=path.name,
                bits=parsed.bits,
            )
        )
    return entries


def _parse_authorized_keys(path: Path, errors: list[str]) -> list[AuthorizedKeyEntry]:
    entries: list[AuthorizedKeyEntry] = []
    if not path.exists():
        return entries
    try:
        text = _read_text(path)
    except OSError as exc:
        errors.append(f"无法读取 {path.name}: {exc}")
        return entries
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.strip().startswith("#"):
            continue
        parsed = parse_public_key_line(line)
        if parsed is None:
            continue
        entries.append(
            AuthorizedKeyEntry(
                key_type=parsed.key_type,
                fingerprint=parsed.fingerprint,
                bits=parsed.bits,
                comment=parsed.comment,
                options=parsed.options,
                line=number,
                source=str(path),
            )
        )
    return entries


def _parse_config_text(
    text: str,
    source: str,
    base_dir: Path,
    errors: list[str],
    depth: int = 0,
) -> list[HostConfig]:
    hosts: list[HostConfig] = []
    if depth > 4:
        return hosts

    current_aliases: list[str] = []
    current_line = 0
    options: dict[str, str] = {}
    identity_files: list[str] = []
    match_mode = False

    def flush() -> None:
        nonlocal current_aliases, options, identity_files, current_line
        if not current_aliases or not options:
            current_aliases = []
            options = {}
            identity_files = []
            return
        for alias in current_aliases:
            hostname = options.get("hostname", "")
            host = HostConfig(
                alias=alias,
                hostname=hostname,
                user=options.get("user", ""),
                port=options.get("port", ""),
                identity_files=list(identity_files),
                proxy_jump=options.get("proxyjump", ""),
                options={k: v for k, v in options.items() if k not in ("hostname", "user", "port", "proxyjump")},
                source=source,
                line=current_line,
                is_pattern=any(char in alias for char in "*?!"),
            )
            hosts.append(host)
        current_aliases = []
        options = {}
        identity_files = []

    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("match "):
            flush()
            match_mode = True
            continue
        key, _, value = line.partition(" ")
        key = key.strip().lower()
        value = value.strip()
        if key == "host":
            flush()
            match_mode = False
            current_aliases = value.split()
            current_line = number
            continue
        if match_mode:
            continue
        if key == "include":
            pattern = value.strip('"')
            target = Path(pattern).expanduser()
            if not target.is_absolute():
                target = base_dir / target
            for filename in glob.glob(str(target)):
                try:
                    included = Path(filename)
                    included_text = _read_text(included)
                except OSError as exc:
                    errors.append(f"无法读取 Include {filename}: {exc}")
                    continue
                hosts.extend(
                    _parse_config_text(
                        included_text,
                        str(included),
                        included.parent,
                        errors,
                        depth + 1,
                    )
                )
            continue
        if current_aliases:
            options[key] = value
            if key == "identityfile":
                identity_files.append(value)
    flush()
    return hosts


def _read_configs(
    errors: list[str],
    ssh_dir: Path | None = None,
) -> tuple[list[HostConfig], dict[str, str], list[str]]:
    hosts: list[HostConfig] = []
    raws: dict[str, str] = {}
    files: list[str] = []
    user_config = (ssh_dir / "config") if ssh_dir else (default_ssh_dir() / "config")
    for path in (user_config, _system_client_config()):
        if not path.is_file():
            continue
        try:
            text = _read_text(path)
        except OSError as exc:
            errors.append(f"无法读取配置 {path}: {exc}")
            continue
        raws[str(path)] = text
        files.append(str(path))
        hosts.extend(_parse_config_text(text, str(path), path.parent, errors))

    # Prefer user entries when the same alias appears in both files.
    deduped: dict[tuple[str, str], HostConfig] = {}
    for host in hosts:
        key = (host.alias, host.source)
        deduped[key] = host
    return list(deduped.values()), raws, files


def _scan_agent(errors: list[str]) -> AgentStatus:
    add_path = _find_tool("ssh-add")
    if not add_path:
        return AgentStatus(available=False, running=False, message="未检测到 ssh-add")
    try:
        proc = _run([add_path, "-l"], timeout=5)
    except (OSError, subprocess.SubprocessError) as exc:
        return AgentStatus(available=True, running=False, message=str(exc))
    output = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode == 0:
        keys: list[AgentKey] = []
        pattern = re.compile(r"^\s*(\d+)\s+(SHA256:\S+)\s+(.*?)\s+\(([^)]+)\)\s*$")
        for line in proc.stdout.splitlines():
            match = pattern.match(line)
            if not match:
                continue
            keys.append(
                AgentKey(
                    bits=int(match.group(1)),
                    fingerprint=match.group(2),
                    comment=match.group(3).strip(),
                    key_type=match.group(4).strip(),
                )
            )
        return AgentStatus(available=True, running=True, keys=keys)
    if proc.returncode == 1 and "no identities" in output.lower():
        return AgentStatus(available=True, running=True, keys=[], message="agent 中没有已加载的密钥")
    if proc.returncode == 2 and "no identities" in output.lower():
        return AgentStatus(available=True, running=True, keys=[], message="agent 中没有已加载的密钥")
    lowered = output.lower()
    if any(
        marker in lowered
        for marker in (
            "error connecting",
            "could not open a connection",
            "no such file or directory",
            "failed to connect",
        )
    ):
        return AgentStatus(available=True, running=False, message="ssh-agent 未运行或无法连接")
    message = output.strip() or "无法连接 ssh-agent"
    return AgentStatus(available=True, running=False, message=message)


def _scan_server(errors: list[str]) -> ServerInfo:
    info = ServerInfo()
    if os.name == "nt":
        try:
            proc = _run(["sc.exe", "query", "sshd"], timeout=5)
            output = (proc.stdout or "") + (proc.stderr or "")
            info.installed = "SERVICE_NAME" in output.upper()
            state_match = re.search(r"STATE\s*:\s*\d+\s+(\w+)", output, re.IGNORECASE)
            if state_match:
                info.state = state_match.group(1).upper()
            info.running = info.state == "RUNNING"
            if not info.installed:
                info.state = "未安装"
        except (OSError, subprocess.SubprocessError) as exc:
            errors.append(f"无法查询 sshd 服务: {exc}")
    else:
        for marker in ("/run/sshd.pid", "/var/run/sshd.pid"):
            if Path(marker).exists():
                info.installed = info.running = True
                info.state = "RUNNING"
                break

    sshd_config = _system_ssh_dir() / "sshd_config"
    info.config_path = str(sshd_config) if sshd_config.exists() else ""
    if sshd_config.exists():
        try:
            text = _read_text(sshd_config)
            for raw_line in text.splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                key, _, value = line.partition(" ")
                key = key.lower()
                value = value.strip().lower()
                if key == "passwordauthentication":
                    info.password_auth = value == "yes"
                elif key == "pubkeyauthentication":
                    info.pubkey_auth = value == "yes"
                elif key == "permitrootlogin":
                    info.permit_root = value
        except OSError as exc:
            errors.append(f"无法读取 sshd_config: {exc}")

    host_dir = _system_ssh_dir()
    for suffix in ("_key.pub", "_key"):
        try:
            candidates = sorted(host_dir.glob(f"ssh_host_*{suffix}"))
        except OSError:
            candidates = []
        for path in candidates:
            if suffix == "_key" and path.with_name(path.name + ".pub").exists():
                continue
            try:
                if path.suffix == ".pub":
                    parsed = parse_public_key_line(_read_text(path))
                else:
                    private = read_private_key(path)
                    if not private.blob:
                        continue
                    parsed = parse_public_key_line(
                        f"{private.key_type} {base64.b64encode(private.blob).decode('ascii')}"
                    )
            except (OSError, SSHFormatError, ValueError):
                continue
            if parsed:
                info.host_keys.append(parsed)
        if info.host_keys:
            break
    return info


# ---------------------------------------------------------------------------
# Audit


def _duplicate_fingerprints(keys: Iterable[KeyRecord]) -> set[str]:
    seen: dict[str, int] = {}
    for key in keys:
        if key.fingerprint:
            seen[key.fingerprint] = seen.get(key.fingerprint, 0) + 1
    return {fingerprint for fingerprint, count in seen.items() if count > 1}


def _build_findings(result: ScanResult) -> list[Finding]:
    findings: list[Finding] = []
    keys = result.keys

    if not keys:
        findings.append(
            Finding(
                "info",
                "尚未配置 SSH 密钥",
                "在你的 SSH 目录中没有发现密钥对。生成密钥后即可用于 Git 托管、服务器登录等场景。",
                "点击“生成密钥”，推荐选择 Ed25519 并设置口令。",
                "密钥",
            )
        )

    duplicates = _duplicate_fingerprints(key for key in keys if key.has_private)
    for key in keys:
        if key.has_private:
            if key.encrypted is False:
                findings.append(
                    Finding(
                        "warning",
                        f"{key.name} 没有口令保护",
                        "私钥以未加密形式保存在磁盘上。任何能读取该文件的人都可以直接使用这个身份。",
                        "使用 ssh-keygen -p -f <私钥> 设置口令，或在生成时填写口令。",
                        "密钥",
                    )
                )
            if key.pair_mismatch:
                findings.append(
                    Finding(
                        "critical",
                        f"{key.name} 的公私钥不匹配",
                        "公钥文件中的公钥与私钥包含的公钥不一致，使用该密钥对会导致认证失败或身份混淆。",
                        "确认私钥对应的正确公钥，删除错误的 .pub 后执行 ssh-keygen -y -f <私钥> 重新导出。",
                        "密钥",
                    )
                )
            if key.permission_warning:
                findings.append(
                    Finding(
                        "warning",
                        f"{key.name} 的私钥权限过宽",
                        f"检测到 {key.permission_warning}。其他本地账户可能读取该私钥。",
                        "将私钥权限限制为当前用户（Windows 可执行 icacls <私钥> /inheritance:r /grant:r \"%USERNAME%:F\"）。",
                        "权限",
                    )
                )
            if key.key_type == "ssh-dss":
                findings.append(
                    Finding(
                        "critical",
                        f"{key.name} 使用 DSA 算法",
                        "DSA 已被 OpenSSH 弃用，且默认密钥长度不足。",
                        "生成新的 Ed25519 或 RSA 3072+ 密钥，并替换服务器上的旧公钥。",
                        "密钥",
                    )
                )
            elif key.key_type == "ssh-rsa" and key.bits:
                if key.bits < 2048:
                    findings.append(
                        Finding(
                            "critical",
                            f"{key.name} 的 RSA 密钥仅 {key.bits} 位",
                            "低于 2048 位的 RSA 密钥已无法提供足够的安全强度。",
                            "生成至少 3072 位的 RSA 密钥，或改用 Ed25519。",
                            "密钥",
                        )
                    )
                elif key.bits < 3072:
                    findings.append(
                        Finding(
                            "warning",
                            f"{key.name} 的 RSA 密钥为 {key.bits} 位",
                            "2048 位 RSA 仍可用，但 3072 位以上更符合当前建议。",
                            "在方便时轮换为 3072 位或 4096 位 RSA，或改用 Ed25519。",
                            "密钥",
                        )
                    )
            if key.fingerprint in duplicates:
                findings.append(
                    Finding(
                        "warning",
                        f"{key.name} 的密钥被重复使用",
                        "相同指纹的私钥出现在多个文件中。重复副本会扩大私钥泄露面，也容易造成轮换遗漏。",
                        "保留一份受口令保护的私钥，删除其他副本或改为引用同一文件。",
                        "密钥",
                    )
                )
            if key.certificate:
                cert = key.certificate
                if cert.expired:
                    findings.append(
                        Finding(
                            "warning",
                            f"{key.name} 的 SSH 证书已过期",
                            f"证书 {cert.key_id or '(无 key id)'} 已超过有效期，使用它登录会被拒绝。",
                            "向 CA 重新申请证书，或清理过期的 -cert.pub 文件。",
                            "证书",
                        )
                    )
                elif cert.not_yet_valid:
                    findings.append(
                        Finding(
                            "info",
                            f"{key.name} 的 SSH 证书尚未生效",
                            "证书的生效时间在未来，当前无法用于认证。",
                            "确认本机时钟和证书有效期是否正确。",
                            "证书",
                        )
                    )
        else:
            findings.append(
                Finding(
                    "info",
                    f"{key.name} 只有公钥",
                    "发现公钥文件但没有对应的私钥，可能是从其他设备复制的授权记录。",
                    "如果需要在当前设备使用该身份，请导入对应私钥。",
                    "密钥",
                )
            )

    if result.directory_warning:
        findings.append(
            Finding(
                "warning",
                "SSH 目录权限过宽",
                f"{result.ssh_dir} 检测到 {result.directory_warning}。宽松的目录权限可能让其他本地账户读取或替换密钥。",
                "将目录权限限制为当前用户：Windows 可执行 icacls <SSH目录> /inheritance:r /grant:r \"%USERNAME%:F\"。",
                "权限",
            )
        )

    if result.known_hosts:
        revoked = [entry for entry in result.known_hosts if entry.is_revoked]
        if revoked:
            findings.append(
                Finding(
                    "critical",
                    "known_hosts 中存在已撤销的主机密钥",
                    f"发现 {len(revoked)} 条 @revoked 记录，说明对应主机密钥已被明确标记为不可信。",
                    "确认主机密钥轮换情况；不要手动删除撤销标记后继续连接。",
                    "已知主机",
                )
            )
    else:
        findings.append(
            Finding(
                "info",
                "还没有已知主机记录",
                "首次连接服务器时会提示确认主机指纹，确认后会写入 known_hosts。",
                "连接前通过可信渠道核对服务器主机指纹。",
                "已知主机",
            )
        )

    for entry in result.authorized_keys:
        if entry.key_type == "ssh-dss":
            findings.append(
                Finding(
                    "critical",
                    "authorized_keys 中存在 DSA 公钥",
                    f"{entry.source_name} 第 {entry.line} 行的密钥使用已被弃用的 DSA 算法，允许它登录会扩大攻击面。",
                    "从 authorized_keys 中移除该 DSA 公钥，改用 Ed25519 或 RSA 3072+。",
                    "授权密钥",
                )
            )
        elif entry.key_type == "ssh-rsa" and entry.bits and entry.bits < 2048:
            findings.append(
                Finding(
                    "warning",
                    "authorized_keys 中存在弱 RSA 公钥",
                    f"{entry.source_name} 第 {entry.line} 行的 RSA 密钥只有 {entry.bits} 位。",
                    "移除该授权公钥，改用至少 3072 位的 RSA 或 Ed25519。",
                    "授权密钥",
                )
            )

    for host in result.hosts:
        strict = host.options.get("stricthostkeychecking", "").lower()
        if strict in ("no", "off", "false"):
            findings.append(
                Finding(
                    "warning",
                    f"主机 {host.alias} 关闭了主机密钥校验",
                    "StrictHostKeyChecking=no 会让客户端自动接受未知主机密钥，容易受到中间人攻击。",
                    "移除该配置，或改为 accept-new 并在首次连接时核对指纹。",
                    "配置",
                )
            )
        known_hosts = host.options.get("userknownhostsfile", "").lower()
        if known_hosts in ("/dev/null", "nul", "none"):
            findings.append(
                Finding(
                    "warning",
                    f"主机 {host.alias} 禁用了 known_hosts",
                    "UserKnownHostsFile 指向空设备，连接时将无法检测主机密钥变化。",
                    "恢复默认的 known_hosts 路径，或使用集中管理的 known_hosts 文件。",
                    "配置",
                )
            )
        if host.options.get("forwardagent", "").lower() == "yes":
            findings.append(
                Finding(
                    "info",
                    f"主机 {host.alias} 启用了 Agent 转发",
                    "将本地 ssh-agent 转发到远端后，拥有远端管理员权限的人可能借用你的密钥。",
                    "仅在确实需要跳板认证时启用 ForwardAgent。",
                    "配置",
                )
            )

    server = result.server
    if server.installed and server.running:
        if server.password_auth is True:
            findings.append(
                Finding(
                    "warning",
                    "本机 sshd 允许密码登录",
                    "密码登录可能遭受暴力破解。已配置公钥时，关闭密码认证可以显著降低风险。",
                    "在 sshd_config 中设置 PasswordAuthentication no，然后重启 sshd 服务。",
                    "本机服务",
                )
            )
        if server.pubkey_auth is False:
            findings.append(
                Finding(
                    "warning",
                    "本机 sshd 关闭了公钥认证",
                    "关闭公钥认证通常意味着只能使用密码登录，与本机管理密钥的目标不一致。",
                    "在 sshd_config 中设置 PubkeyAuthentication yes。",
                    "本机服务",
                )
            )
        if server.permit_root.lower() in ("yes", "prohibit-password", "without-password"):
            findings.append(
                Finding(
                    "warning",
                    "本机 sshd 允许 root 登录",
                    "直接开放 root 远程登录会增加高风险攻击面。",
                    "设置 PermitRootLogin no，改用普通账户登录后再提权。",
                    "本机服务",
                )
            )

    if result.ssh_add_path and not result.agent.running:
        findings.append(
            Finding(
                "info",
                "ssh-agent 未运行",
                "把常用密钥加载到 agent 后，可以为受口令保护的私钥提供一次解锁、多次使用。",
                "Windows 可启动 OpenSSH Authentication Agent 服务后执行 ssh-add。",
                "agent",
            )
        )

    severity_order = {"critical": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda item: severity_order.get(item.severity, 3))
    return findings


def _calculate_score(findings: list[Finding]) -> tuple[int, str]:
    critical = sum(1 for item in findings if item.severity == "critical")
    warning = sum(1 for item in findings if item.severity == "warning")
    score = max(8, 100 - critical * 24 - warning * 8)
    if score >= 90:
        grade = "优秀"
    elif score >= 75:
        grade = "良好"
    elif score >= 60:
        grade = "需关注"
    else:
        grade = "有风险"
    return score, grade


def scan_system(ssh_dir: str | Path | None = None) -> ScanResult:
    directory = Path(ssh_dir).expanduser().resolve() if ssh_dir else default_ssh_dir()
    result = ScanResult(ssh_dir=str(directory))
    result.exists = directory.is_dir()

    ssh_path = _find_tool("ssh")
    keygen_path = _find_tool("ssh-keygen")
    add_path = _find_tool("ssh-add")
    result.ssh_path = ssh_path
    result.keygen_path = keygen_path
    result.ssh_add_path = add_path
    result.ssh_version = detect_ssh_version(ssh_path)

    if not result.exists:
        result.errors.append(f"SSH 目录不存在：{directory}")

    result.directory_warning = _windows_acl_issue(directory) if result.exists else None
    try:
        result.keys, result.certificates, result.total_files = _scan_keys(directory, result.errors)
    except Exception as exc:  # defensive: scanning must never take the UI down
        result.errors.append(f"扫描密钥时出错: {exc}")

    result.known_hosts = _parse_known_hosts(directory / "known_hosts", result.errors)
    old_hosts = directory / "known_hosts.old"
    if old_hosts.exists():
        try:
            result.known_hosts_old_count = len(_parse_known_hosts(old_hosts, []))
        except Exception:
            pass

    try:
        result.hosts, result.raw_configs, result.config_files = _read_configs(result.errors, directory)
    except Exception as exc:
        result.errors.append(f"解析 SSH 配置时出错: {exc}")

    result.agent = _scan_agent(result.errors)
    result.server = _scan_server(result.errors)

    for candidate in (directory / "authorized_keys", _system_ssh_dir() / "administrators_authorized_keys"):
        result.authorized_keys.extend(_parse_authorized_keys(candidate, result.errors))
    result.authorized_keys_count = len(result.authorized_keys)

    result.findings = _build_findings(result)
    result.score, result.grade = _calculate_score(result.findings)
    return result


# ---------------------------------------------------------------------------
# Key generation


@dataclass(slots=True)
class GenerationResult:
    ok: bool
    message: str = ""
    key: KeyRecord | None = None
    private_path: str = ""
    public_path: str = ""
    fingerprint: str = ""
    agent_added: bool = False
    agent_message: str = ""
    stdout: str = ""
    stderr: str = ""

    @property
    def public_key(self) -> str:
        return self.key.public_key if self.key else ""


_INVALID_FILENAME = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def validate_key_name(name: str) -> str | None:
    if not name:
        return "请输入密钥文件名"
    if name in (".", ".."):
        return "文件名不合法"
    if _INVALID_FILENAME.search(name):
        return "文件名不能包含 < > : \" / \\ | ? * 等字符"
    if name.endswith((".pub", ".ppk", ".pem")):
        return "请填写不带扩展名的文件名"
    if len(name) > 120:
        return "文件名过长"
    return None


def default_key_name(key_type: str) -> str:
    return {
        "ed25519": "id_ed25519",
        "rsa": "id_rsa",
        "ecdsa": "id_ecdsa",
    }.get(key_type, "id_ed25519")


def add_to_agent(private_path: str, passphrase: str = "") -> tuple[bool, str]:
    if passphrase:
        return False, "受口令保护的密钥需要手动执行 ssh-add 并输入口令"
    add_path = _find_tool("ssh-add")
    if not add_path:
        return False, "未检测到 ssh-add"
    try:
        proc = _run([add_path, private_path], timeout=8)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    if proc.returncode == 0:
        return True, "已添加到 ssh-agent"
    message = (proc.stderr or proc.stdout or "ssh-add 执行失败").strip()
    if any(marker in message.lower() for marker in ("error connecting", "could not open a connection")):
        return False, "ssh-agent 未运行，请先启动 OpenSSH Authentication Agent"
    return False, message


def generate_ssh_key(
    *,
    key_type: str,
    directory: str | Path,
    name: str,
    comment: str = "",
    passphrase: str = "",
    bits: int | None = None,
    add_agent: bool = False,
) -> GenerationResult:
    error = validate_key_name(name)
    if error:
        return GenerationResult(False, error)
    if key_type not in ("ed25519", "rsa", "ecdsa"):
        return GenerationResult(False, "不支持的密钥类型")
    if key_type == "rsa" and int(bits or 3072) not in (2048, 3072, 4096, 8192):
        return GenerationResult(False, "RSA 密钥长度必须是 2048、3072、4096 或 8192 位")
    if key_type == "ecdsa" and int(bits or 256) not in (256, 384, 521):
        return GenerationResult(False, "ECDSA 曲线必须是 P-256、P-384 或 P-521")

    if _serialization is None:
        return GenerationResult(False, "缺少 cryptography 依赖，无法生成密钥")

    target_dir = Path(directory).expanduser().resolve()
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return GenerationResult(False, f"无法创建目录：{exc}")

    private_path = target_dir / name
    public_path = target_dir / f"{name}.pub"
    if private_path.exists() or public_path.exists():
        return GenerationResult(False, f"{private_path.name} 已存在，请换一个文件名")

    try:
        if key_type == "ed25519":
            private_key = _ed25519.Ed25519PrivateKey.generate()
        elif key_type == "rsa":
            private_key = _rsa.generate_private_key(public_exponent=65537, key_size=int(bits or 3072))
        elif key_type == "ecdsa":
            curve_map = {
                256: _ec.SECP256R1(),
                384: _ec.SECP384R1(),
                521: _ec.SECP521R1(),
            }
            private_key = _ec.generate_private_key(curve_map.get(int(bits or 256), _ec.SECP256R1()))
        else:
            return GenerationResult(False, "不支持的密钥类型")

        encryption = (
            _serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
            if passphrase
            else _serialization.NoEncryption()
        )
        private_bytes = private_key.private_bytes(
            encoding=_serialization.Encoding.PEM,
            format=_serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=encryption,
        )
        public_line = private_key.public_key().public_bytes(
            encoding=_serialization.Encoding.OpenSSH,
            format=_serialization.PublicFormat.OpenSSH,
        ).decode("ascii")
        if comment:
            public_line += f" {comment}"

        # O_EXCL makes the no-overwrite guarantee atomic even if two instances
        # of the app generate a key at the same time.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        fd = os.open(str(private_path), flags, 0o600)
        try:
            os.write(fd, private_bytes)
        finally:
            os.close(fd)
        try:
            public_path.write_text(public_line + "\n", encoding="utf-8", newline="\n")
        except OSError:
            try:
                private_path.unlink()
            except OSError:
                pass
            raise
    except PermissionError as exc:
        return GenerationResult(
            False,
            f"无法写入 {target_dir}：权限不足。请确认目录可写，并从普通桌面或终端启动 KeyGuard（不要使用受限沙箱）。原始错误：{exc}",
        )
    except (OSError, ValueError) as exc:
        return GenerationResult(False, f"生成失败：{exc}")
    except Exception as exc:  # e.g. bcrypt missing for encrypted OpenSSH keys
        return GenerationResult(False, f"生成失败：{exc}")

    _harden_private_key(private_path)

    record: KeyRecord | None = None
    try:
        keys, _, _ = _scan_keys(target_dir, [])
        record = next((item for item in keys if item.private_path == str(private_path.resolve())), None)
    except Exception:
        pass

    parsed_public = parse_public_key_line(public_line)
    result = GenerationResult(
        ok=True,
        message="密钥生成成功",
        key=record,
        private_path=str(private_path),
        public_path=str(public_path) if public_path.exists() else "",
        fingerprint=(record.fingerprint if record else (parsed_public.fingerprint if parsed_public else "")),
    )
    if add_agent and not passphrase:
        added, message = add_to_agent(str(private_path))
        result.agent_added = added
        result.agent_message = message
    return result
