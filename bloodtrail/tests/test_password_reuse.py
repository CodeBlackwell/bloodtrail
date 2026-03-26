"""
Unit tests for password reuse analysis.

Tests credential tracking and reuse detection.
"""

import unittest
from bloodtrail.core.password_reuse import (
    ReuseAnalysis,
    SpraySuggestion,
    PasswordReuseTracker,
)
from bloodtrail.core.models import (
    DiscoveredCredential,
    SecretType,
    SourceType,
    Confidence,
)


class TestPasswordReuseTracker(unittest.TestCase):
    """Tests for password reuse tracking."""

    def setUp(self):
        self.tracker = PasswordReuseTracker()
        self.context = {"target_ip": "10.10.10.172", "domain": "MEGABANK.LOCAL"}

    def test_add_credential(self):
        """Should track added credentials."""
        cred = DiscoveredCredential(
            username="mhope",
            secret="Password123",
            source_type=SourceType.CONFIG_FILE,
        )

        result = self.tracker.add_credential(cred)

        self.assertTrue(result)  # New credential

    def test_duplicate_detection(self):
        """Should detect and reject duplicates."""
        cred1 = DiscoveredCredential(username="mhope", secret="Password123")
        cred2 = DiscoveredCredential(username="mhope", secret="Password123")

        self.assertTrue(self.tracker.add_credential(cred1))
        self.assertFalse(self.tracker.add_credential(cred2))  # Duplicate

    def test_case_insensitive_username(self):
        """Username comparison should be case-insensitive."""
        cred1 = DiscoveredCredential(username="mhope", secret="Password123")
        cred2 = DiscoveredCredential(username="MHOPE", secret="Password123")

        self.assertTrue(self.tracker.add_credential(cred1))
        self.assertFalse(self.tracker.add_credential(cred2))

    def test_analyze_reuse_detection(self):
        """Should detect password reuse across accounts."""
        shared_password = "SharedSecret123"

        self.tracker.add_credential(DiscoveredCredential(
            username="user1", secret=shared_password
        ))
        self.tracker.add_credential(DiscoveredCredential(
            username="user2", secret=shared_password
        ))
        self.tracker.add_credential(DiscoveredCredential(
            username="user3", secret="UniquePassword"
        ))

        analysis = self.tracker.analyze_reuse()

        self.assertEqual(analysis.total_credentials, 3)
        self.assertEqual(analysis.unique_passwords, 2)
        self.assertEqual(analysis.reused_count, 1)
        self.assertIn(shared_password, analysis.reused_passwords)

    def test_reuse_rate_calculation(self):
        """Should calculate reuse rate percentage."""
        # Add 4 creds: 2 share password, 2 unique
        self.tracker.add_credential(DiscoveredCredential(username="a", secret="shared"))
        self.tracker.add_credential(DiscoveredCredential(username="b", secret="shared"))
        self.tracker.add_credential(DiscoveredCredential(username="c", secret="unique1"))
        self.tracker.add_credential(DiscoveredCredential(username="d", secret="unique2"))

        analysis = self.tracker.analyze_reuse()

        # 1 out of 3 unique passwords is reused = 33.3%
        self.assertAlmostEqual(analysis.reuse_rate, 33.33, delta=1)

    def test_shares_password_with(self):
        """Should find users sharing password."""
        self.tracker.add_credential(DiscoveredCredential(username="admin", secret="Admin123"))
        self.tracker.add_credential(DiscoveredCredential(username="backup", secret="Admin123"))
        self.tracker.add_credential(DiscoveredCredential(username="other", secret="Other123"))

        analysis = self.tracker.analyze_reuse()
        shared = analysis.shares_password_with("admin")

        self.assertIn("backup", shared)
        self.assertNotIn("other", shared)
        self.assertNotIn("admin", shared)  # Should not include self

    def test_spray_candidates_prioritization(self):
        """Should prioritize reused passwords for spraying."""
        # Reused password
        self.tracker.add_credential(DiscoveredCredential(
            username="svc_sql", secret="Service123",
            confidence=Confidence.CONFIRMED
        ))
        self.tracker.add_credential(DiscoveredCredential(
            username="svc_backup", secret="Service123",
            confidence=Confidence.CONFIRMED
        ))

        # Unique password
        self.tracker.add_credential(DiscoveredCredential(
            username="user", secret="UniquePass"
        ))

        candidates = self.tracker.get_spray_candidates()

        # Reused password should be first
        self.assertEqual(candidates[0][0], "Service123")

    def test_spray_suggestions_generated(self):
        """Should generate spray suggestions with educational context."""
        self.tracker.add_credential(DiscoveredCredential(
            username="admin", secret="Password1",
            confidence=Confidence.CONFIRMED
        ))

        suggestions = self.tracker.get_spray_suggestions(["user1", "user2"], self.context)

        self.assertGreater(len(suggestions), 0)

        # Check educational explanation exists
        for s in suggestions:
            self.assertTrue(len(s.explanation) > 0, f"Missing explanation: {s.action}")

    def test_spray_suggestions_include_command(self):
        """Spray suggestions should include runnable commands."""
        self.tracker.add_credential(DiscoveredCredential(
            username="svc", secret="ServicePwd"
        ))

        suggestions = self.tracker.get_spray_suggestions(["user1"], self.context)

        # At least one should have a crackmapexec or similar command
        cmd_suggestions = [s for s in suggestions if "crackmapexec" in s.command.lower()]
        self.assertGreater(len(cmd_suggestions), 0)

    def test_lateral_movement_suggestions(self):
        """Should suggest lateral movement for password reuse."""
        self.tracker.add_credential(DiscoveredCredential(
            username="current_user", secret="SharedPwd"
        ))
        self.tracker.add_credential(DiscoveredCredential(
            username="target_user", secret="SharedPwd"
        ))

        suggestions = self.tracker.get_lateral_movement_paths("current_user", self.context)

        self.assertGreater(len(suggestions), 0)
        self.assertIn("target_user", suggestions[0].target_users)

    def test_reuse_report_generation(self):
        """Should generate human-readable report."""
        self.tracker.add_credential(DiscoveredCredential(username="a", secret="shared"))
        self.tracker.add_credential(DiscoveredCredential(username="b", secret="shared"))

        report = self.tracker.get_reuse_report()

        self.assertIn("PASSWORD REUSE ANALYSIS", report)
        self.assertIn("REUSED PASSWORDS", report)
        self.assertIn("EDUCATIONAL NOTES", report)


class TestReuseAnalysis(unittest.TestCase):
    """Tests for ReuseAnalysis dataclass."""

    def test_empty_analysis(self):
        """Empty analysis should have zero values."""
        analysis = ReuseAnalysis()

        self.assertEqual(analysis.total_credentials, 0)
        self.assertEqual(analysis.unique_passwords, 0)
        self.assertEqual(analysis.reuse_rate, 0.0)

    def test_get_users_with_password(self):
        """Should return users with specific password."""
        analysis = ReuseAnalysis(
            by_password={"secret123": ["user1", "user2"]}
        )

        users = analysis.get_users_with_password("secret123")

        self.assertEqual(users, ["user1", "user2"])

    def test_get_users_unknown_password(self):
        """Should return empty list for unknown password."""
        analysis = ReuseAnalysis()

        users = analysis.get_users_with_password("nonexistent")

        self.assertEqual(users, [])


class TestSpraySuggestion(unittest.TestCase):
    """Tests for SpraySuggestion dataclass."""

    def test_spray_suggestion_fields(self):
        """SpraySuggestion should have all required fields."""
        suggestion = SpraySuggestion(
            action="Spray with reused password",
            command="crackmapexec smb 10.10.10.172 -u users.txt -p 'Password1'",
            explanation="This password is reused across multiple accounts",
            priority=1,
            password="Password1",
            success_likelihood="high",
        )

        self.assertEqual(suggestion.action, "Spray with reused password")
        self.assertIn("crackmapexec", suggestion.command)
        self.assertEqual(suggestion.success_likelihood, "high")


if __name__ == "__main__":
    unittest.main()
