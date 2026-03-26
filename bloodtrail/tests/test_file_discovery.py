"""
Unit tests for file discovery framework.

Tests file scoring and interest heuristics.
"""

import unittest
from bloodtrail.core.file_discovery import (
    DiscoveredFile,
    FileDiscoveryBase,
    LocalFileDiscovery,
)


class TestDiscoveredFile(unittest.TestCase):
    """Tests for DiscoveredFile dataclass."""

    def test_full_path(self):
        """Should combine source and path correctly."""
        f = DiscoveredFile(path="Users/mhope/azure.xml", source="smb://10.10.10.172/users$")
        self.assertEqual(f.full_path, "smb://10.10.10.172/users$/Users/mhope/azure.xml")

    def test_filename_extraction(self):
        """Should extract filename from path."""
        f = DiscoveredFile(path="deep/nested/config.xml", source="/local")
        self.assertEqual(f.filename, "config.xml")

    def test_extension_extraction(self):
        """Should extract lowercase extension."""
        f = DiscoveredFile(path="file.XML", source="/local")
        self.assertEqual(f.extension, ".xml")


class TestFileScoring(unittest.TestCase):
    """Tests for file interest scoring."""

    def setUp(self):
        # Create a concrete implementation for testing
        self.discovery = LocalFileDiscovery("/tmp")

    def test_high_value_filename_score(self):
        """High-value filenames should get high scores."""
        high_value_files = [
            "groups.xml",     # GPP passwords
            "azure.xml",      # Azure credentials
            "unattend.xml",   # Windows deployment
            "web.config",     # .NET config
            ".env",           # Environment variables
            "passwords.txt",  # Obvious password file
        ]

        for filename in high_value_files:
            f = DiscoveredFile(path=filename, source="/test", size=1000)
            score = self.discovery.score_file(f)
            self.assertGreaterEqual(score, 40, f"{filename} should score >= 40, got {score}")

    def test_interesting_extension_score(self):
        """Interesting extensions should add to score."""
        extensions = [".xml", ".config", ".json", ".ps1", ".env", ".key"]

        for ext in extensions:
            f = DiscoveredFile(path=f"somefile{ext}", source="/test", size=5000)
            score = self.discovery.score_file(f)
            self.assertGreater(score, 0, f"{ext} should have score > 0")

    def test_interesting_directory_score(self):
        """Files in interesting directories should score higher."""
        paths = [
            "sysvol/Policies/config.xml",
            "backup/database.sql",
            ".ssh/id_rsa",
            "credentials/api.json",
        ]

        for path in paths:
            f = DiscoveredFile(path=path, source="/test", size=1000)
            score = self.discovery.score_file(f)
            self.assertGreaterEqual(score, 15, f"{path} should score >= 15")

    def test_small_file_bonus(self):
        """Small files (likely configs) should get bonus."""
        # Small file
        small = DiscoveredFile(path="config.xml", source="/test", size=5000)
        small_score = self.discovery.score_file(small)

        # Large file
        large = DiscoveredFile(path="config.xml", source="/test", size=50_000_000)
        large_score = self.discovery.score_file(large)

        self.assertGreater(small_score, large_score)

    def test_skip_patterns(self):
        """Should skip binary and system files."""
        skip_files = [
            "program.exe",
            "library.dll",
            "image.png",
            "video.mp4",
            "desktop.ini",
            "thumbs.db",
        ]

        for filename in skip_files:
            should_skip = self.discovery.should_skip(filename)
            self.assertTrue(should_skip, f"{filename} should be skipped")

    def test_not_skip_interesting_files(self):
        """Should not skip interesting files."""
        keep_files = [
            "config.xml",
            "passwords.txt",
            "script.ps1",
            ".env",
        ]

        for filename in keep_files:
            should_skip = self.discovery.should_skip(filename)
            self.assertFalse(should_skip, f"{filename} should NOT be skipped")

    def test_score_reasons_tracked(self):
        """Score reasons should be tracked for transparency."""
        f = DiscoveredFile(
            path="sysvol/Policies/Groups.xml",
            source="/test",
            size=1000
        )
        self.discovery.score_file(f)

        # Should have reasons
        self.assertGreater(len(f.score_reasons), 0)
        # Should mention extension and/or filename
        reasons_str = " ".join(f.score_reasons)
        self.assertTrue(
            "extension" in reasons_str or "filename" in reasons_str or "dir" in reasons_str,
            f"Reasons should explain score: {f.score_reasons}"
        )


class TestDiscoverySummary(unittest.TestCase):
    """Tests for discovery summary generation."""

    def setUp(self):
        self.discovery = LocalFileDiscovery("/tmp")

    def test_summary_categorization(self):
        """Summary should categorize by priority."""
        files = [
            DiscoveredFile(path="groups.xml", source="/test", interesting_score=85),
            DiscoveredFile(path="config.json", source="/test", interesting_score=45),
            DiscoveredFile(path="readme.txt", source="/test", interesting_score=10),
        ]

        summary = self.discovery.get_discovery_summary(files)

        self.assertEqual(summary['high_priority'], 1)
        self.assertEqual(summary['medium_priority'], 1)
        self.assertEqual(summary['low_priority'], 1)
        self.assertEqual(summary['total_files'], 3)

    def test_summary_top_files(self):
        """Summary should include top scored files."""
        files = [
            DiscoveredFile(path=f"file{i}.xml", source="/test", interesting_score=i*10)
            for i in range(1, 15)
        ]

        summary = self.discovery.get_discovery_summary(files)

        # Top 10 files should be sorted by score descending
        self.assertEqual(len(summary['top_files']), 10)
        self.assertEqual(summary['top_files'][0].interesting_score, 140)


if __name__ == "__main__":
    unittest.main()
