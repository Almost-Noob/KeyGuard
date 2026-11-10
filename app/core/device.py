"""Stable device identity and hardware fingerprint collection."""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import platform
import re
import socket
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    import psutil
except Exception:  # pragma: no cover - optional at import time
    psutil = None


_INVALID_IDS = {
    "",
    "none",
    "0",
    "default string",
    "to be filled by o.e.m.",
    "to be filled by oem",
    "not specified",
    "not applicable",
    "system serial number",
    "system manufacturer",
    "system product name",
    "system version",
    "oem",
    "unknown",
    "n/a",
    "00000000-0000-0000-0000-000000000000",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
    "03000200-0400-0500-0006-000700080009",
}


@dataclass(slots=True)
class FingerprintComponent:
    key: str
    label: str
    value: str
    icon: str = "mdi.identifier"
    category: str = "硬件"
    sensitive: bool = False
    hint: str = ""

    @property
    def value_hash(self) -> str:
        if not self.value:
            return "—"
        digest = hashlib.sha256(f"{self.key}:{self.value}".encode("utf-8")).hexdigest()[:12]
        return f"{digest[:6]}-{digest[6:]}".upper()

    @property
    def is_empty(self) -> bool:
        return not self.value.strip()

    @property
    def display_value(self) -> str:
        return self.value if self.value.strip() else "不可用"


@dataclass(slots=True)
class DeviceFingerprint:
    device_id: str
    short_id: str
    components: list[FingerprintComponent] = field(default_factory=list)
    hostname: str = ""
    username: str = ""
    os_name: str = ""
    os_version: str = ""
    architecture: str = ""
    manufacturer: str = ""
    model: str = ""
    collected_at: datetime = field(default_factory=datetime.now)
    stable_count: int = 0
    warning: str = ""

    @property
    def stable_components(self) -> list[FingerprintComponent]:
        return [item for item in self.components if item.key in _STABLE_KEYS]

    def to_export_dict(self) -> dict[str, Any]:
        return {
            "schema": "keyguard.device-fingerprint/v1",
            "generated_at": self.collected_at.astimezone().isoformat(timespec="seconds"),
            "device_id": self.device_id,
            "short_id": self.short_id,
            "hostname": self.hostname,
            "username": self.username,
            "os": {
                "name": self.os_name,
                "version": self.os_version,
                "architecture": self.architecture,
            },
            "manufacturer": self.manufacturer,
            "model": self.model,
            "components": [
                {
                    "key": item.key,
                    "label": item.label,
                    "value": item.value,
                    "value_hash": item.value_hash,
                    "sensitive": item.sensitive,
                }
                for item in self.components
                if item.value
            ],
            "note": (
                "The device_id is a SHA-256 digest of stable hardware identifiers, "
                "computed locally. Raw identifiers are included above; handle this "
                "export as sensitive data."
            ),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_export_dict(), ensure_ascii=False, indent=indent)


_STABLE_KEYS = {
    "machine_guid",
    "computer_hardware_id",
    "smbios_uuid",
    "bios_serial",
    "board_serial",
    "cpu_id",
    "system_volume",
}


def _clean(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if text.lower() in _INVALID_IDS:
        return ""
    return text


def _run_powershell(script: str, timeout: float = 12.0) -> dict[str, Any]:
    if os.name != "nt":
        return {}
    exe = "powershell.exe"
    command = (
        "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"
        "$ErrorActionPreference='SilentlyContinue';" + script
    )
    try:
        proc = subprocess.run(
            [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    raw = (proc.stdout or "").strip()
    if not raw:
        return {}
    if not raw.startswith("{"):
        start = raw.find("{")
        end = raw.rfind("}")
        if start == -1 or end == -1:
            return {}
        raw = raw[start : end + 1]
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _machine_guid() -> str:
    if os.name == "nt":
        try:
            import winreg

            access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
                0,
                access,
            ) as key:
                value, _ = winreg.QueryValueEx(key, "MachineGuid")
                if isinstance(value, str):
                    return value
        except OSError:
            pass
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            text = Path(path).read_text(encoding="utf-8").strip()
            if text:
                return text
        except OSError:
            continue
    return ""


def _volume_serial() -> tuple[str, str]:
    if os.name != "nt":
        return "", ""
    root = os.environ.get("SystemDrive", "C:") + "\\"
    try:
        serial = ctypes.c_uint()
        ok = ctypes.windll.kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(root),
            None,
            0,
            ctypes.byref(serial),
            None,
            None,
            None,
            0,
        )
        if ok:
            return f"{serial.value:08X}", root
    except Exception:
        pass
    return "", root


def _format_mac(raw: str) -> str:
    digits = re.sub(r"[^0-9A-Fa-f]", "", raw)
    if len(digits) != 12:
        return raw.upper()
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2)).upper()


def _network_interfaces() -> list[FingerprintComponent]:
    if psutil is None:
        return []
    try:
        stats = psutil.net_if_addrs()
        io = psutil.net_if_stats()
    except Exception:
        return []
    skip_words = (
        "virtual",
        "vmware",
        "vbox",
        "loopback",
        "bluetooth",
        "wsl",
        "hyper-v",
        "vethernet",
        "tap",
        "tun",
        "npcap",
        "pseudo",
    )
    result: list[FingerprintComponent] = []
    for name in sorted(stats):
        lowered = name.lower()
        if any(word in lowered for word in skip_words):
            continue
        if re.search(r"(wlan|wi-?fi)\s+\d+$", lowered):
            continue
        mac = ""
        for address in stats[name]:
            if getattr(address, "family", None) == psutil.AF_LINK:
                candidate = (address.address or "").replace("-", ":").upper()
                if candidate and candidate != "00:00:00:00:00:00":
                    mac = _format_mac(candidate)
                    break
        if not mac:
            continue
        try:
            up = io[name].isup
        except Exception:
            up = False
        result.append(
            FingerprintComponent(
                key=f"mac_{len(result)}",
                label=f"网卡 · {name}",
                value=mac,
                icon="mdi.ethernet",
                category="网络",
                sensitive=True,
                hint="网络适配器物理地址" if up else "网络适配器物理地址（当前未连接）",
            )
        )
        if len(result) >= 3:
            break
    if not result:
        node = uuid.getnode()
        if node and (node & 0x010000000000) == 0:
            mac = ":".join(f"{(node >> (8 * i)) & 0xFF:02X}" for i in range(5, -1, -1))
            result.append(
                FingerprintComponent(
                    key="mac_0",
                    label="主网卡",
                    value=mac,
                    icon="mdi.ethernet",
                    category="网络",
                    sensitive=True,
                )
            )
    return result


def _windows_registry_info() -> dict[str, str]:
    """Read system identity from the registry.

    CIM/WMI can be unavailable to restricted users or blocked by security
    software, while these stable keys are normally readable by the current
    user.
    """

    if os.name != "nt":
        return {}
    try:
        import winreg
    except ImportError:  # pragma: no cover
        return {}

    sources: dict[str, list[tuple[str, str]]] = {
        "BIOS": [
            ("SystemManufacturer", "Manufacturer"),
            ("SystemProductName", "Model"),
            ("SystemVersion", "SystemVersion"),
            ("BaseBoardManufacturer", "BoardManufacturer"),
            ("BaseBoardProduct", "BoardProduct"),
            ("BaseBoardVersion", "BoardVersion"),
            ("BIOSVersion", "BiosVersion"),
            ("BIOSReleaseDate", "BiosReleaseDate"),
            ("BIOSVendor", "BiosVendor"),
        ],
        "CPU": [
            ("ProcessorNameString", "CpuName"),
            ("Identifier", "CpuIdentifier"),
            ("VendorIdentifier", "CpuVendor"),
        ],
        "OS": [
            ("ProductName", "OsCaption"),
            ("DisplayVersion", "OsDisplayVersion"),
            ("CurrentBuildNumber", "OsBuild"),
            ("UBR", "OsUbr"),
        ],
        "SYSTEM": [
            ("ComputerHardwareId", "ComputerHardwareId"),
            ("SystemManufacturer", "SystemManufacturer"),
            ("SystemProductName", "SystemProductName"),
            ("BIOSVersion", "SystemBiosVersion"),
        ],
    }
    paths = {
        "BIOS": r"HARDWARE\DESCRIPTION\System\BIOS",
        "CPU": r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
        "OS": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "SYSTEM": r"SYSTEM\CurrentControlSet\Control\SystemInformation",
    }
    result: dict[str, str] = {}
    for group, values in sources.items():
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, paths[group], 0, winreg.KEY_READ) as key:
                for value_name, output_name in values:
                    try:
                        value, _ = winreg.QueryValueEx(key, value_name)
                    except OSError:
                        continue
                    if isinstance(value, str) and value.strip():
                        result[output_name] = value.strip()
        except OSError:
            continue
    return result


def _windows_info() -> dict[str, Any]:
    script = r"""
$cs=Get-CimInstance Win32_ComputerSystem | Select-Object -First 1
$bios=Get-CimInstance Win32_BIOS | Select-Object -First 1
$bb=Get-CimInstance Win32_BaseBoard | Select-Object -First 1
$cpu=Get-CimInstance Win32_Processor | Select-Object -First 1
$os=Get-CimInstance Win32_OperatingSystem | Select-Object -First 1
$csp=Get-CimInstance Win32_ComputerSystemProduct | Select-Object -First 1
$disk=Get-CimInstance Win32_DiskDrive | Where-Object {$_.SerialNumber} | Select-Object -First 1
[pscustomobject]@{
  Manufacturer=$cs.Manufacturer; Model=$cs.Model; ComputerName=$cs.Name;
  TotalMemory=$cs.TotalPhysicalMemory; CsUuid=$csp.UUID;
  BiosSerial=$bios.SerialNumber; BiosVersion=$bios.SMBIOSBIOSVersion;
  BoardSerial=$bb.SerialNumber; BoardProduct=$bb.Product; BoardManufacturer=$bb.Manufacturer;
  CpuName=$cpu.Name; CpuId=$cpu.ProcessorId; CpuCores=$cpu.NumberOfCores; CpuThreads=$cpu.NumberOfLogicalProcessors;
  OsCaption=$os.Caption; OsVersion=$os.Version; OsBuild=$os.BuildNumber; OsArch=$os.OSArchitecture;
  DiskModel=$disk.Model; DiskSerial=$disk.SerialNumber; DiskSize=$disk.Size; DiskInterface=$disk.InterfaceType
} | ConvertTo-Json -Compress
"""
    return _run_powershell(script)


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _human_bytes(value: int) -> str:
    if value <= 0:
        return ""
    units = ("B", "KB", "MB", "GB", "TB")
    size = float(value)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.0f} {unit}" if unit in ("B", "KB") else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _linux_dmi(name: str) -> str:
    try:
        return Path(f"/sys/class/dmi/id/{name}").read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def collect_device_fingerprint() -> DeviceFingerprint:
    win: dict[str, Any] = {}
    if os.name == "nt":
        win = _windows_info()
        registry = _windows_registry_info()
        for key, value in registry.items():
            if not _clean(win.get(key)):
                win[key] = value
    hostname = _clean(win.get("ComputerName")) or socket.gethostname()
    username = os.environ.get("USERNAME") or os.environ.get("USER") or ""

    os_caption = _clean(win.get("OsCaption"))
    if not os_caption:
        os_caption = f"{platform.system()} {platform.release()}".strip()
    os_version = ""
    build = _clean(win.get("OsBuild"))
    ubr = _clean(win.get("OsUbr"))
    display = _clean(win.get("OsDisplayVersion"))
    if build:
        os_version = f"Build {build}" + (f".{ubr}" if ubr else "")
        if display:
            os_version = f"{display} · {os_version}"
    elif win.get("OsVersion"):
        os_version = _clean(win.get("OsVersion"))
    else:
        os_version = platform.version()
    architecture = _clean(win.get("OsArch")) or platform.machine()
    if os_caption.startswith("Windows 10") and build.isdigit() and int(build) >= 22000:
        os_caption = os_caption.replace("Windows 10", "Windows 11", 1)

    machine_guid = _machine_guid()
    computer_hardware_id = _clean(win.get("ComputerHardwareId"))
    smbios_uuid = _clean(win.get("CsUuid"))
    if not smbios_uuid and os.name != "nt":
        smbios_uuid = _linux_dmi("product_uuid")

    bios_serial = _clean(win.get("BiosSerial")) or (_linux_dmi("product_serial") if os.name != "nt" else "")
    board_serial = _clean(win.get("BoardSerial")) or (_linux_dmi("board_serial") if os.name != "nt" else "")
    board_product = _clean(win.get("BoardProduct")) or (_linux_dmi("board_name") if os.name != "nt" else "")
    cpu_id = _clean(win.get("CpuId"))
    cpu_name = _clean(win.get("CpuName")) or platform.processor() or "未知处理器"
    disk_serial = _clean(win.get("DiskSerial"))
    disk_model = _clean(win.get("DiskModel"))
    volume_serial, system_root = _volume_serial()

    manufacturer = _clean(win.get("Manufacturer")) or _clean(win.get("SystemManufacturer")) or (
        _linux_dmi("sys_vendor") if os.name != "nt" else ""
    )
    model = _clean(win.get("Model")) or _clean(win.get("SystemProductName")) or (
        _linux_dmi("product_name") if os.name != "nt" else ""
    )
    if model.lower() in ("system product name", "system version"):
        model = ""

    components: list[FingerprintComponent] = []

    def add(
        key: str,
        label: str,
        value: str,
        icon: str,
        category: str,
        sensitive: bool = False,
        hint: str = "",
    ) -> None:
        components.append(
            FingerprintComponent(
                key=key,
                label=label,
                value=value,
                icon=icon,
                category=category,
                sensitive=sensitive,
                hint=hint,
            )
        )

    if machine_guid:
        add("machine_guid", "系统 Machine ID", machine_guid, "mdi.identifier", "系统", True, "安装系统时生成，重装后会变化")
    if computer_hardware_id:
        add(
            "computer_hardware_id",
            "Windows 硬件 ID",
            computer_hardware_id,
            "mdi.fingerprint",
            "系统",
            True,
            "Windows 根据硬件组合生成的稳定标识",
        )
    if smbios_uuid:
        add("smbios_uuid", "SMBIOS UUID", smbios_uuid, "mdi.chip", "硬件", True, "主板固件中的系统唯一标识")
    if bios_serial:
        add("bios_serial", "BIOS 序列号", bios_serial, "mdi.memory", "硬件", True)
    if board_serial:
        add("board_serial", "主板序列号", board_serial, "mdi.developer-board", "硬件", True)
    if cpu_id:
        add("cpu_id", "CPU 处理器 ID", cpu_id, "mdi.cpu-64-bit", "硬件", True, "部分 CPU 不提供稳定的 ProcessorId")
    if volume_serial:
        add("system_volume", f"系统盘卷序列号 · {system_root}", volume_serial, "mdi.harddisk", "存储", True)
    if disk_serial:
        add("disk_serial", "物理磁盘序列号", disk_serial, "mdi.harddisk-plus", "存储", True, disk_model)
    components.extend(_network_interfaces())
    add("hostname", "计算机名", hostname, "mdi.laptop", "系统", False)
    add("os", "操作系统", os_caption, "mdi.microsoft-windows", "系统", False, os_version)
    add("cpu_model", "处理器型号", cpu_name, "mdi.cpu-64-bit", "硬件", False)
    cores = _safe_int(win.get("CpuCores"))
    threads = _safe_int(win.get("CpuThreads"))
    if psutil is not None:
        if not cores:
            try:
                cores = psutil.cpu_count(logical=False) or 0
            except Exception:
                cores = 0
        if not threads:
            try:
                threads = psutil.cpu_count(logical=True) or 0
            except Exception:
                threads = 0
    if cores or threads:
        add(
            "cpu_topology",
            "CPU 核心 / 线程",
            f"{cores or '—'} 核 / {threads or '—'} 线程",
            "mdi.chip",
            "硬件",
            False,
        )
    memory = _safe_int(win.get("TotalMemory"))
    if not memory and psutil is not None:
        try:
            memory = psutil.virtual_memory().total
        except Exception:
            memory = 0
    if memory:
        add("memory", "物理内存", _human_bytes(memory), "mdi.memory", "硬件", False)
    if board_product:
        add("board_model", "主板型号", board_product, "mdi.developer-board", "硬件", False)
    bios_version = _clean(win.get("BiosVersion"))
    if bios_version:
        add(
            "bios_version",
            "BIOS 版本",
            bios_version,
            "mdi.memory",
            "硬件",
            False,
            _clean(win.get("BiosReleaseDate")),
        )

    stable_pairs: list[tuple[str, str]] = []
    for item in components:
        if item.key in _STABLE_KEYS and item.value:
            stable_pairs.append((item.key, item.value))

    if len(stable_pairs) < 2:
        stable_pairs.extend(
            [
                ("hostname", hostname),
                ("os", os_caption),
                ("arch", architecture),
            ]
        )
    canonical = "\n".join(f"{key}={value.strip().upper()}" for key, value in stable_pairs)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    short = base64.b32encode(bytes.fromhex(digest)).decode("ascii")[:16]
    short_id = "-".join(short[i : i + 4] for i in range(0, 16, 4))

    warning = ""
    if len(stable_pairs) < 2:
        warning = "未能读取足够的硬件标识，指纹将回退到主机名与系统信息，稳定性较低。"

    return DeviceFingerprint(
        device_id=digest,
        short_id=short_id,
        components=components,
        hostname=hostname,
        username=username,
        os_name=os_caption,
        os_version=os_version,
        architecture=architecture,
        manufacturer=manufacturer,
        model=model,
        stable_count=len([pair for pair in stable_pairs if pair[0] in _STABLE_KEYS]),
        warning=warning,
    )


def mask_value(value: str, keep_start: int = 3, keep_end: int = 3) -> str:
    if not value:
        return "—"
    if len(value) <= 4:
        return "•" * len(value)
    if len(value) <= keep_start + keep_end + 1:
        head = max(1, min(2, len(value) // 3))
        tail = max(1, min(2, len(value) // 3))
        return f"{value[:head]}{'•' * max(2, len(value) - head - tail)}{value[-tail:]}"
    return f"{value[:keep_start]}{'•' * min(18, len(value) - keep_start - keep_end)}{value[-keep_end:]}"
