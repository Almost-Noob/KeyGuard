from __future__ import annotations

import base64
import hashlib
import shutil
import unittest
from pathlib import Path

from app.core.device import collect_device_fingerprint, mask_value
from app.core.ssh import (
    generate_ssh_key,
    parse_public_key_line,
    read_private_key,
    scan_system,
)

WORK = Path(".tmp") / "unit-ssh"
KEY_DIR = WORK / "keys"
CONFIG_DIR = WORK / "config"


def setUpModule() -> None:
    shutil.rmtree(WORK, ignore_errors=True)
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def tearDownModule() -> None:
    shutil.rmtree(WORK, ignore_errors=True)


class PublicKeyTests(unittest.TestCase):
    def test_ed25519_known_hosts_line(self) -> None:
        line = (
            "192.168.1.74 ssh-ed25519 "
            "AAAAC3NzaC1lZDI1NTE5AAAAIEs6KZH79ND2yhP127GM2lJVcbdc1jAFlDfMsXkzwgnL"
        )
        parsed = parse_public_key_line(line.split(" ", 1)[1])
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.key_type, "ssh-ed25519")
        self.assertEqual(parsed.bits, 256)
        self.assertTrue(parsed.fingerprint.startswith("SHA256:"))
        self.assertEqual(
            parsed.fingerprint,
            "SHA256:" + base64.b64encode(hashlib.sha256(parsed.blob).digest()).decode().rstrip("="),
        )

    def test_authorized_keys_options_and_comment(self) -> None:
        line = (
            'command="/usr/bin/backup",no-pty ssh-ed25519 '
            "AAAAC3NzaC1lZDI1NTE5AAAAIEs6KZH79ND2yhP127GM2lJVcbdc1jAFlDfMsXkzwgnL deploy@backup"
        )
        parsed = parse_public_key_line(line)
        self.assertIsNotNone(parsed)
        self.assertIn("no-pty", parsed.options)
        self.assertEqual(parsed.comment, "deploy@backup")

    def test_garbage_is_rejected(self) -> None:
        self.assertIsNone(parse_public_key_line("not a key"))
        self.assertIsNone(parse_public_key_line("# comment"))


class GenerationAndScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ed = generate_ssh_key(
            key_type="ed25519",
            directory=KEY_DIR,
            name="id_ed25519",
            comment="unit@test",
            passphrase="",
        )
        cls.rsa = generate_ssh_key(
            key_type="rsa",
            directory=KEY_DIR,
            name="id_rsa",
            comment="encrypted@test",
            passphrase="correct horse battery staple",
            bits=2048,
        )

    def test_generate_ed25519(self) -> None:
        self.assertTrue(self.ed.ok, self.ed.message)
        self.assertTrue((KEY_DIR / "id_ed25519").exists())
        self.assertTrue((KEY_DIR / "id_ed25519.pub").exists())
        self.assertTrue((KEY_DIR / "id_ed25519.pub").read_text().endswith("unit@test\n"))
        self.assertTrue(self.ed.fingerprint.startswith("SHA256:"))

    def test_generate_encrypted_rsa(self) -> None:
        self.assertTrue(self.rsa.ok, self.rsa.message)
        parsed = read_private_key(KEY_DIR / "id_rsa")
        self.assertTrue(parsed.encrypted)
        self.assertEqual(parsed.bits, 2048)

    def test_refuses_overwrite(self) -> None:
        result = generate_ssh_key(
            key_type="ed25519",
            directory=KEY_DIR,
            name="id_ed25519",
            passphrase="",
        )
        self.assertFalse(result.ok)
        self.assertIn("已存在", result.message)

    def test_invalid_name(self) -> None:
        result = generate_ssh_key(
            key_type="ed25519",
            directory=KEY_DIR,
            name="../escape",
            passphrase="",
        )
        self.assertFalse(result.ok)

    def test_scan_finds_pair_and_metadata(self) -> None:
        result = scan_system(KEY_DIR)
        names = {key.name for key in result.keys}
        self.assertIn("id_ed25519", names)
        self.assertIn("id_rsa", names)
        ed = next(key for key in result.keys if key.name == "id_ed25519")
        rsa = next(key for key in result.keys if key.name == "id_rsa")
        self.assertTrue(ed.has_private and ed.has_public)
        self.assertFalse(ed.encrypted)
        self.assertEqual(ed.comment, "unit@test")
        self.assertTrue(rsa.encrypted)
        self.assertEqual(rsa.bits, 2048)
        self.assertEqual(result.private_count, 2)
        self.assertGreaterEqual(result.public_count, 2)


class ConfigAndAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dir = CONFIG_DIR
        cls.dir.mkdir(parents=True, exist_ok=True)
        (cls.dir / "known_hosts").write_text(
            "example.com ssh-ed25519 "
            "AAAAC3NzaC1lZDI1NTE5AAAAIEs6KZH79ND2yhP127GM2lJVcbdc1jAFlDfMsXkzwgnL\n"
            "@revoked old.example.com ssh-ed25519 "
            "AAAAC3NzaC1lZDI1NTE5AAAAIEs6KZH79ND2yhP127GM2lJVcbdc1jAFlDfMsXkzwgnL\n",
            encoding="utf-8",
        )
        (cls.dir / "config").write_text(
            "Host *\n"
            "    ServerAliveInterval 30\n"
            "\n"
            "Host alpha\n"
            "    HostName alpha.example.com\n"
            "    User deploy\n"
            "    Port 2222\n"
            "    IdentityFile ~/.ssh/id_alpha\n"
            "\n"
            "Host beta\n"
            "    HostName 10.0.0.5\n"
            "    User root\n"
            "    IdentityFile ~/.ssh/id_one\n"
            "    IdentityFile ~/.ssh/id_two\n",
            encoding="utf-8",
        )
        (cls.dir / "authorized_keys").write_text(
            "command=\"/usr/bin/backup\",no-pty ssh-ed25519 "
            "AAAAC3NzaC1lZDI1NTE5AAAAIEs6KZH79ND2yhP127GM2lJVcbdc1jAFlDfMsXkzwgnL deploy@backup\n",
            encoding="utf-8",
        )
        cls.scan = scan_system(cls.dir)

    def test_authorized_keys(self) -> None:
        self.assertEqual(self.scan.authorized_keys_count, 1)
        entry = self.scan.authorized_keys[0]
        self.assertEqual(entry.comment, "deploy@backup")
        self.assertTrue(entry.is_restricted)
        self.assertEqual(entry.source_name, "authorized_keys")

    def test_config_hosts(self) -> None:
        aliases = {host.alias for host in self.scan.hosts}
        self.assertIn("alpha", aliases)
        self.assertIn("beta", aliases)
        beta = next(host for host in self.scan.hosts if host.alias == "beta")
        self.assertEqual(beta.user, "root")
        self.assertEqual(len(beta.identity_files), 2)

    def test_known_hosts(self) -> None:
        self.assertEqual(self.scan.unique_known_hosts, 2)
        self.assertTrue(any(entry.is_revoked for entry in self.scan.known_hosts))

    def test_revoked_finding(self) -> None:
        titles = [finding.title for finding in self.scan.findings]
        self.assertTrue(any("撤销" in title for title in titles))

    def test_score_range(self) -> None:
        self.assertGreaterEqual(self.scan.score, 0)
        self.assertLessEqual(self.scan.score, 100)
        self.assertIn(self.scan.grade, ("优秀", "良好", "需关注", "有风险"))


class DeviceFingerprintTests(unittest.TestCase):
    def test_stable_sha256(self) -> None:
        first = collect_device_fingerprint()
        second = collect_device_fingerprint()
        self.assertEqual(len(first.device_id), 64)
        self.assertTrue(all(char in "0123456789abcdef" for char in first.device_id))
        self.assertEqual(first.device_id, second.device_id)
        self.assertEqual(first.short_id.count("-"), 3)
        self.assertGreaterEqual(len(first.components), 3)

    def test_export_is_json(self) -> None:
        import json

        fp = collect_device_fingerprint()
        data = json.loads(fp.to_json())
        self.assertEqual(data["schema"], "keyguard.device-fingerprint/v1")
        self.assertEqual(data["device_id"], fp.device_id)

    def test_mask(self) -> None:
        self.assertIn("•", mask_value("ABCDEF1234567890"))
        self.assertEqual(mask_value(""), "—")


if __name__ == "__main__":
    unittest.main()
