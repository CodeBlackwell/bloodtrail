"""
Unit tests for service account analyzer.

Tests service account identification and prioritization.
"""

import unittest
from bloodtrail.core.service_accounts import (
    AccountPriority,
    AttackVector,
    ServiceAccountInfo,
    AnalysisResult,
    ServiceAccountAnalyzer,
)


class TestServiceAccountAnalyzer(unittest.TestCase):
    """Tests for service account analysis."""

    def setUp(self):
        self.analyzer = ServiceAccountAnalyzer()
        self.context = {"domain": "MEGABANK.LOCAL", "target_ip": "10.10.10.172"}

    def test_detect_svc_prefix(self):
        """Should detect svc_ prefixed accounts."""
        users = [
            {"name": "svc_sql"},
            {"name": "svc_backup"},
            {"name": "regularuser"},
        ]

        result = self.analyzer.analyze_from_users(users, self.context)

        svc_accounts = [a.name for a in result.all_accounts]
        self.assertIn("svc_sql", svc_accounts)
        self.assertIn("svc_backup", svc_accounts)
        self.assertNotIn("regularuser", svc_accounts)

    def test_detect_sa_prefix(self):
        """Should detect sa_ prefixed accounts."""
        users = [{"name": "SA_Database"}]

        result = self.analyzer.analyze_from_users(users, self.context)

        self.assertEqual(len(result.all_accounts), 1)
        self.assertIn("sa- prefix", result.all_accounts[0].patterns_matched)

    def test_detect_sql_accounts(self):
        """Should detect SQL service accounts."""
        users = [
            {"name": "sqlserver"},
            {"name": "mssql_svc"},
            {"name": "mysql_admin"},
        ]

        result = self.analyzer.analyze_from_users(users, self.context)

        self.assertGreaterEqual(len(result.all_accounts), 2)

    def test_kerberoastable_detection(self):
        """Should detect Kerberoastable accounts (with SPN)."""
        users = [
            {"name": "svc_http", "spn": "HTTP/webserver.corp.local"},
        ]

        result = self.analyzer.analyze_from_users(users, self.context)

        self.assertEqual(len(result.all_accounts), 1)
        account = result.all_accounts[0]
        self.assertTrue(account.has_spn)
        self.assertIn(AttackVector.KERBEROAST, account.attack_vectors)
        self.assertIn("Kerberoast", account.attack_suggestion)

    def test_asrep_roastable_detection(self):
        """Should detect AS-REP roastable accounts."""
        users = [
            {"name": "svc_legacy", "dontreqpreauth": True},
        ]

        result = self.analyzer.analyze_from_users(users, self.context)

        account = result.all_accounts[0]
        self.assertTrue(account.preauth_disabled)
        self.assertIn(AttackVector.ASREP_ROAST, account.attack_vectors)

    def test_password_in_description_detection(self):
        """Should detect passwords in description field."""
        users = [
            {"name": "svc_backup", "description": "Backup service - password: Backup123!"},
            {"name": "svc_normal", "description": "Normal service account"},
        ]

        result = self.analyzer.analyze_from_users(users, self.context)

        pwd_accounts = [a for a in result.all_accounts if AttackVector.PASSWORD_IN_DESC in a.attack_vectors]
        self.assertEqual(len(pwd_accounts), 1)
        self.assertEqual(pwd_accounts[0].name, "svc_backup")
        self.assertIn("DESCRIPTION", pwd_accounts[0].attack_suggestion.upper())

    def test_password_in_description_variants(self):
        """Should detect various password-in-description formats."""
        descriptions = [
            "password: Secret123",
            "pwd = MyPassword",
            "Pass: TestPass",
            "p/w: AdminPwd",
        ]

        for desc in descriptions:
            users = [{"name": "svc_test", "description": desc}]
            result = self.analyzer.analyze_from_users(users, self.context)

            pwd_accounts = [a for a in result.all_accounts if AttackVector.PASSWORD_IN_DESC in a.attack_vectors]
            self.assertEqual(len(pwd_accounts), 1, f"Should detect: {desc}")

    def test_priority_scoring_critical(self):
        """Kerberoastable + password in description = CRITICAL."""
        users = [
            {
                "name": "svc_sql",
                "spn": "MSSQLSvc/db01:1433",
                "description": "SQL Service - pwd: SqlPass123",
            }
        ]

        result = self.analyzer.analyze_from_users(users, self.context)

        self.assertEqual(len(result.critical), 1)

    def test_priority_categorization(self):
        """Should categorize accounts by priority."""
        users = [
            {"name": "svc_sql", "spn": "MSSQLSvc/db:1433"},  # High priority (Kerberoastable + svc pattern)
            {"name": "svc_backup", "dontreqpreauth": True},  # High priority (AS-REP + svc pattern)
            {"name": "svc_web"},  # Lower priority (just naming pattern)
        ]

        result = self.analyzer.analyze_from_users(users, self.context)

        # All should be detected as service accounts
        self.assertEqual(len(result.all_accounts), 3)
        # At least the Kerberoastable and AS-REP accounts should be high priority
        self.assertGreaterEqual(len(result.high_priority), 2)

    def test_educational_notes_generated(self):
        """Each account should have educational context."""
        users = [
            {"name": "svc_sql", "spn": "MSSQLSvc/db:1433"},
        ]

        result = self.analyzer.analyze_from_users(users, self.context)

        account = result.all_accounts[0]
        self.assertTrue(len(account.educational_note) > 0)
        self.assertIn("Kerberoast", account.educational_note)

    def test_next_steps_generated(self):
        """Should generate next step recommendations."""
        users = [
            {"name": "svc_sql", "spn": "MSSQLSvc/db:1433"},
        ]

        result = self.analyzer.analyze_from_users(users, self.context)

        self.assertGreater(len(result.next_steps), 0)
        # Should have Kerberoast suggestion
        kerberoast_steps = [s for s in result.next_steps if "kerberoast" in s["action"].lower()]
        self.assertGreater(len(kerberoast_steps), 0)

    def test_next_steps_have_commands(self):
        """Next steps should include runnable commands."""
        users = [{"name": "svc_sql", "spn": "MSSQLSvc/db:1433"}]

        result = self.analyzer.analyze_from_users(users, self.context)

        for step in result.next_steps:
            self.assertIn("command", step)
            self.assertTrue(len(step["command"]) > 0)

    def test_technology_patterns(self):
        """Should detect technology-specific service accounts."""
        tech_accounts = [
            "exchange_svc",
            "sharepoint_admin",
            "sccm_service",
            "adfs_sync",
            "elastic_indexer",
        ]

        for name in tech_accounts:
            users = [{"name": name}]
            result = self.analyzer.analyze_from_users(users, self.context)

            self.assertGreater(len(result.all_accounts), 0, f"Should detect: {name}")

    def test_admin_pattern_detection(self):
        """Should detect admin-related service accounts."""
        users = [
            {"name": "svc_admin"},
            {"name": "priv_service"},
        ]

        result = self.analyzer.analyze_from_users(users, self.context)

        self.assertGreaterEqual(len(result.all_accounts), 1)

    def test_spray_wordlist_generation(self):
        """Should generate domain-specific password wordlist."""
        wordlist = self.analyzer.get_spray_wordlist("MEGABANK.LOCAL")

        # Base passwords
        self.assertIn("Password1", wordlist)
        self.assertIn("Welcome1", wordlist)

        # Domain-specific
        self.assertTrue(any("Megabank" in p for p in wordlist))

    def test_report_generation(self):
        """Should generate human-readable report."""
        users = [
            {"name": "svc_sql", "spn": "MSSQLSvc/db:1433"},
            {"name": "svc_backup"},
        ]

        result = self.analyzer.analyze_from_users(users, self.context)
        report = self.analyzer.get_report(result)

        self.assertIn("SERVICE ACCOUNT ANALYSIS", report)
        self.assertIn("Critical:", report)
        self.assertIn("RECOMMENDED NEXT STEPS", report)

    def test_no_false_positives(self):
        """Regular users should not be flagged as service accounts."""
        users = [
            {"name": "john.smith"},
            {"name": "jane.doe"},
            {"name": "administrator"},  # Admin, but not service pattern
        ]

        result = self.analyzer.analyze_from_users(users, self.context)

        # Should not flag regular users
        regular_users = [a.name for a in result.all_accounts if a.name in ["john.smith", "jane.doe"]]
        self.assertEqual(len(regular_users), 0)


class TestServiceAccountInfo(unittest.TestCase):
    """Tests for ServiceAccountInfo dataclass."""

    def test_upn_generation(self):
        """Should generate UPN from name and domain."""
        account = ServiceAccountInfo(
            name="svc_sql",
            domain="CORP.LOCAL",
        )

        self.assertEqual(account.upn, "svc_sql@CORP.LOCAL")

    def test_upn_without_domain(self):
        """UPN without domain should just be name."""
        account = ServiceAccountInfo(name="svc_sql")

        self.assertEqual(account.upn, "svc_sql")


class TestAnalysisResult(unittest.TestCase):
    """Tests for AnalysisResult dataclass."""

    def test_add_categorizes_correctly(self):
        """Should add accounts to correct priority bucket."""
        result = AnalysisResult()

        critical = ServiceAccountInfo(name="crit", priority=AccountPriority.CRITICAL)
        high = ServiceAccountInfo(name="high", priority=AccountPriority.HIGH)
        medium = ServiceAccountInfo(name="med", priority=AccountPriority.MEDIUM)
        low = ServiceAccountInfo(name="low", priority=AccountPriority.LOW)

        result.add(critical)
        result.add(high)
        result.add(medium)
        result.add(low)

        self.assertEqual(len(result.critical), 1)
        self.assertEqual(len(result.high), 1)
        self.assertEqual(len(result.medium), 1)
        self.assertEqual(len(result.low), 1)

    def test_all_accounts_property(self):
        """all_accounts should return all accounts."""
        result = AnalysisResult()
        result.add(ServiceAccountInfo(name="a", priority=AccountPriority.CRITICAL))
        result.add(ServiceAccountInfo(name="b", priority=AccountPriority.LOW))

        self.assertEqual(len(result.all_accounts), 2)

    def test_high_priority_property(self):
        """high_priority should return critical + high accounts."""
        result = AnalysisResult()
        result.add(ServiceAccountInfo(name="crit", priority=AccountPriority.CRITICAL))
        result.add(ServiceAccountInfo(name="high", priority=AccountPriority.HIGH))
        result.add(ServiceAccountInfo(name="med", priority=AccountPriority.MEDIUM))

        self.assertEqual(len(result.high_priority), 2)


if __name__ == "__main__":
    unittest.main()
