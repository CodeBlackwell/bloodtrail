"""
Unit tests for attack vector detection framework.

Tests detection of Azure AD Connect, GPP, LAPS, and other attack vectors.
"""

import unittest
from bloodtrail.core.detection import (
    DetectionConfidence,
    AttackCommand,
    DetectionResult,
    DetectorBase,
    AzureADConnectDetector,
    GPPPasswordDetector,
    LAPSDetector,
    DetectorRegistry,
    get_default_registry,
)


class TestAzureADConnectDetector(unittest.TestCase):
    """Tests for Azure AD Connect detection."""

    def setUp(self):
        self.detector = AzureADConnectDetector()
        self.context = {"target_ip": "10.10.10.172", "domain": "MEGABANK.LOCAL"}

    def test_detect_msol_account(self):
        """Should detect MSOL_ sync accounts."""
        users = [
            {"name": "MSOL_abc123", "upn": "MSOL_abc123@megabank.local"},
            {"name": "mhope", "upn": "mhope@megabank.local"},
        ]
        groups = []
        computers = []

        result = self.detector.detect_from_ldap(users, groups, computers, self.context)

        self.assertIsNotNone(result)
        self.assertEqual(result.indicator, "azure_ad_connect")
        self.assertIn(DetectionConfidence.LIKELY, [result.confidence, DetectionConfidence.CONFIRMED])
        self.assertGreater(len(result.evidence), 0)
        self.assertIn("MSOL", result.evidence[0])

    def test_detect_aad_account(self):
        """Should detect AAD_ sync accounts."""
        users = [
            {"name": "AAD_SyncService", "upn": "AAD_SyncService@corp.local"},
        ]

        result = self.detector.detect_from_ldap(users, [], [], self.context)

        self.assertIsNotNone(result)
        self.assertIn("AAD", result.evidence[0])

    def test_detect_adsync_admins_group(self):
        """Should detect ADSyncAdmins group and members."""
        groups = [
            {"name": "ADSyncAdmins", "members": ["mhope", "admin"]},
        ]

        result = self.detector.detect_from_ldap([], groups, [], self.context)

        self.assertIsNotNone(result)
        self.assertIn("Azure group", result.evidence[0])
        self.assertIn("mhope", result.evidence[1])

    def test_confirmed_with_both_indicators(self):
        """Should have CONFIRMED confidence when both sync account and group exist."""
        users = [{"name": "MSOL_abc123"}]
        groups = [{"name": "ADSyncAdmins", "members": ["mhope"]}]

        result = self.detector.detect_from_ldap(users, groups, [], self.context)

        self.assertEqual(result.confidence, DetectionConfidence.CONFIRMED)

    def test_no_detection_without_indicators(self):
        """Should return None when no Azure indicators present."""
        users = [{"name": "normaluser"}]
        groups = [{"name": "Domain Users"}]

        result = self.detector.detect_from_ldap(users, groups, [], self.context)

        self.assertIsNone(result)

    def test_attack_commands_generated(self):
        """Should generate exploitation commands."""
        commands = self.detector.get_exploit_commands(self.context)

        self.assertGreater(len(commands), 0)
        # Should have sqlcmd for ADSync database
        sqlcmd_cmds = [c for c in commands if "sqlcmd" in c.command.lower() or "adsync" in c.command.lower()]
        self.assertGreater(len(sqlcmd_cmds), 0)

    def test_attack_commands_have_educational_context(self):
        """Each command should have explanation."""
        commands = self.detector.get_exploit_commands(self.context)

        for cmd in commands:
            self.assertTrue(len(cmd.explanation) > 0, f"Command missing explanation: {cmd.description}")

    def test_next_steps_provided(self):
        """Detection should include next steps."""
        users = [{"name": "MSOL_abc123"}]

        result = self.detector.detect_from_ldap(users, [], [], self.context)

        self.assertGreater(len(result.next_steps), 0)

    def test_references_provided(self):
        """Detection should include reference URLs."""
        users = [{"name": "MSOL_abc123"}]

        result = self.detector.detect_from_ldap(users, [], [], self.context)

        self.assertGreater(len(result.references), 0)
        self.assertTrue(any("http" in r for r in result.references))


class TestGPPPasswordDetector(unittest.TestCase):
    """Tests for GPP cpassword detection."""

    def setUp(self):
        self.detector = GPPPasswordDetector()
        self.context = {"target_ip": "10.10.10.172"}

    def test_gpp_detection_suggests_sysvol(self):
        """GPP detection should suggest checking SYSVOL."""
        result = self.detector.detect_from_ldap([], [], [], self.context)

        # GPP requires SYSVOL access, so LDAP detection returns suggestion
        self.assertIsNotNone(result)
        self.assertIn("SYSVOL", result.evidence[0])

    def test_attack_commands_include_cme(self):
        """Should suggest crackmapexec gpp_password module."""
        commands = self.detector.get_exploit_commands(self.context)

        cme_cmds = [c for c in commands if "crackmapexec" in c.command.lower()]
        self.assertGreater(len(cme_cmds), 0)

    def test_attack_commands_include_gpp_decrypt(self):
        """Should suggest gpp-decrypt tool."""
        commands = self.detector.get_exploit_commands(self.context)

        decrypt_cmds = [c for c in commands if "gpp-decrypt" in c.command.lower()]
        self.assertGreater(len(decrypt_cmds), 0)


class TestLAPSDetector(unittest.TestCase):
    """Tests for LAPS detection."""

    def setUp(self):
        self.detector = LAPSDetector()
        self.context = {"target_ip": "10.10.10.172", "domain": "CORP.LOCAL"}

    def test_attack_commands_include_laps_dump(self):
        """Should suggest LAPS password dump commands."""
        commands = self.detector.get_exploit_commands(self.context)

        self.assertGreater(len(commands), 0)
        # Should have crackmapexec or ldapsearch
        cmd_text = " ".join(c.command for c in commands).lower()
        self.assertTrue("laps" in cmd_text or "mcs-admpwd" in cmd_text.lower())


class TestDetectorRegistry(unittest.TestCase):
    """Tests for detector registry."""

    def setUp(self):
        self.registry = get_default_registry()

    def test_default_registry_has_detectors(self):
        """Default registry should have all detectors."""
        detectors = self.registry.list_detectors()

        self.assertGreaterEqual(len(detectors), 3)
        names = [d["indicator"] for d in detectors]
        self.assertIn("azure_ad_connect", names)
        self.assertIn("gpp_password", names)
        self.assertIn("laps", names)

    def test_detect_all_ldap(self):
        """Should run all detectors and return results."""
        users = [{"name": "MSOL_abc123"}]
        groups = [{"name": "ADSyncAdmins", "members": ["mhope"]}]
        context = {"target_ip": "10.10.10.172"}

        results = self.registry.detect_all_ldap(users, groups, [], context)

        # Should have at least Azure detection
        azure_results = [r for r in results if r.indicator == "azure_ad_connect"]
        self.assertGreater(len(azure_results), 0)


class TestDetectionResult(unittest.TestCase):
    """Tests for DetectionResult dataclass."""

    def test_result_truthy_with_evidence(self):
        """Result should be truthy when evidence exists."""
        result = DetectionResult(
            indicator="test",
            name="Test",
            confidence=DetectionConfidence.LIKELY,
            evidence=["Found something"],
        )
        self.assertTrue(bool(result))

    def test_result_falsy_without_evidence(self):
        """Result should be falsy without evidence."""
        result = DetectionResult(
            indicator="test",
            name="Test",
            confidence=DetectionConfidence.POSSIBLE,
            evidence=[],
        )
        self.assertFalse(bool(result))


class TestAttackCommand(unittest.TestCase):
    """Tests for AttackCommand dataclass."""

    def test_command_has_required_fields(self):
        """AttackCommand should have command, description, explanation."""
        cmd = AttackCommand(
            command="evil-winrm -i 10.10.10.172",
            description="Connect via WinRM",
            explanation="WinRM provides PowerShell access",
        )

        self.assertEqual(cmd.command, "evil-winrm -i 10.10.10.172")
        self.assertEqual(cmd.description, "Connect via WinRM")
        self.assertTrue(len(cmd.explanation) > 0)

    def test_command_optional_fields(self):
        """AttackCommand should support optional fields."""
        cmd = AttackCommand(
            command="test",
            description="Test",
            explanation="Test explanation",
            prerequisites=["Admin access"],
            alternatives=["Other method"],
            references=["https://example.com"],
        )

        self.assertEqual(cmd.prerequisites, ["Admin access"])
        self.assertEqual(cmd.alternatives, ["Other method"])
        self.assertEqual(cmd.references, ["https://example.com"])


if __name__ == "__main__":
    unittest.main()
