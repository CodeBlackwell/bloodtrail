"""
Tests for the new CLI UX: subcommand routing, persistent config,
engagement profiles, credential store, doctor, pager, and legacy compat.
"""

import json
import os
import sys
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from bloodtrail.settings import (
    Settings, Engagement, StoredCredential,
    load_settings, save_settings, get_effective_config,
)
from bloodtrail.cli.app import (
    SUBCOMMANDS, create_subcommand_parser,
    _apply_settings_defaults, _handle_config, _handle_query,
)
from bloodtrail.cli import _is_subcommand, main
from bloodtrail.cli.pager import truncate_results, paged_output


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def config_dir(tmp_path, monkeypatch):
    """Redirect config to temp dir so tests don't touch real config."""
    cfg_dir = tmp_path / "config" / "bloodtrail"
    cfg_dir.mkdir(parents=True)
    monkeypatch.setattr("bloodtrail.settings.CONFIG_PATH", cfg_dir / "config.json")
    return cfg_dir


@pytest.fixture
def sample_settings(config_dir):
    """Write a sample config and return the Settings object."""
    s = Settings(
        active_engagement="htb-forest",
        neo4j_uri="bolt://10.10.10.1:7687",
        neo4j_user="neo4j",
        engagements={
            "htb-forest": {
                "name": "htb-forest",
                "dc_ip": "10.10.10.161",
                "domain": "htb.local",
                "domain_sid": "S-1-5-21-1234",
                "dc_hostname": "FOREST",
                "lhost": "10.10.14.5",
                "lport": 443,
                "neo4j_uri": "",
                "neo4j_user": "",
                "credentials": [
                    {"username": "svc-alfresco", "domain": "htb.local",
                     "cred_type": "password", "value": "s3rvice",
                     "validated": True, "source": "kerberoast"},
                ],
            },
            "pg-practice": {
                "name": "pg-practice",
                "dc_ip": "192.168.1.10",
                "domain": "corp.local",
                "domain_sid": "",
                "dc_hostname": "",
                "lhost": "",
                "lport": 443,
                "neo4j_uri": "",
                "neo4j_user": "",
                "credentials": [],
            },
        },
    )
    save_settings(s)
    return s


# =============================================================================
# Settings — StoredCredential
# =============================================================================

class TestStoredCredential:
    def test_label_with_domain(self):
        c = StoredCredential(username="admin", domain="corp.local")
        assert c.label() == "admin@corp.local (password)"

    def test_label_without_domain(self):
        c = StoredCredential(username="admin", cred_type="ntlm-hash")
        assert c.label() == "admin (ntlm-hash)"


# =============================================================================
# Settings — Engagement
# =============================================================================

class TestEngagement:
    def test_add_credential(self):
        eng = Engagement(name="test")
        cred = StoredCredential(username="admin", domain="corp.local", value="pass123")
        eng.add_credential(cred)
        assert len(eng.credentials) == 1
        assert eng.credentials[0]["username"] == "admin"

    def test_add_credential_updates_existing(self):
        eng = Engagement(name="test")
        eng.add_credential(StoredCredential(username="admin", domain="corp.local", value="old"))
        eng.add_credential(StoredCredential(username="admin", domain="corp.local", value="new"))
        assert len(eng.credentials) == 1
        assert eng.credentials[0]["value"] == "new"

    def test_get_credential_case_insensitive(self):
        eng = Engagement(name="test")
        eng.add_credential(StoredCredential(username="Admin", domain="corp.local", value="x"))
        assert eng.get_credential("admin") is not None
        assert eng.get_credential("ADMIN") is not None

    def test_get_credential_missing(self):
        eng = Engagement(name="test")
        assert eng.get_credential("nobody") is None

    def test_list_credentials(self):
        eng = Engagement(name="test")
        eng.add_credential(StoredCredential(username="a", value="1"))
        eng.add_credential(StoredCredential(username="b", value="2"))
        creds = eng.list_credentials()
        assert len(creds) == 2
        assert all(isinstance(c, StoredCredential) for c in creds)


# =============================================================================
# Settings — Settings dataclass
# =============================================================================

class TestSettings:
    def test_create_engagement(self):
        s = Settings()
        eng = s.create_engagement("test-box")
        assert s.active_engagement == "test-box"
        assert "test-box" in s.engagements
        assert eng.name == "test-box"

    def test_get_engagement(self):
        s = Settings()
        s.create_engagement("box1")
        eng = s.get_engagement("box1")
        assert eng is not None
        assert eng.name == "box1"

    def test_get_engagement_missing(self):
        s = Settings()
        assert s.get_engagement("nope") is None

    def test_active_returns_active_engagement(self):
        s = Settings()
        s.create_engagement("active-one")
        assert s.active().name == "active-one"

    def test_active_returns_none_when_empty(self):
        s = Settings()
        assert s.active() is None

    def test_use_switches_engagement(self):
        s = Settings()
        s.create_engagement("a")
        s.create_engagement("b")
        assert s.active_engagement == "b"
        assert s.use("a")
        assert s.active_engagement == "a"

    def test_use_returns_false_for_missing(self):
        s = Settings()
        assert s.use("nonexistent") is False

    def test_list_engagements(self):
        s = Settings()
        s.create_engagement("a")
        s.create_engagement("b")
        assert sorted(s.list_engagements()) == ["a", "b"]

    def test_set_engagement_roundtrip(self):
        s = Settings()
        eng = Engagement(name="x", dc_ip="1.2.3.4", domain="test.local")
        s.set_engagement(eng)
        retrieved = s.get_engagement("x")
        assert retrieved.dc_ip == "1.2.3.4"
        assert retrieved.domain == "test.local"


# =============================================================================
# Settings — Persistence (load/save)
# =============================================================================

class TestSettingsPersistence:
    def test_save_and_load(self, config_dir):
        s = Settings(neo4j_uri="bolt://custom:7687")
        s.create_engagement("saved-box")
        save_settings(s)
        loaded = load_settings()
        assert loaded.neo4j_uri == "bolt://custom:7687"
        assert loaded.active_engagement == "saved-box"

    def test_load_missing_file(self, config_dir):
        s = load_settings()
        assert s.neo4j_uri == "bolt://localhost:7687"
        assert s.engagements == {}

    def test_load_corrupt_file(self, config_dir):
        from bloodtrail.settings import CONFIG_PATH
        CONFIG_PATH.write_text("not json{{{")
        s = load_settings()
        assert isinstance(s, Settings)

    def test_save_creates_directory(self, tmp_path, monkeypatch):
        deep = tmp_path / "a" / "b" / "c" / "config.json"
        monkeypatch.setattr("bloodtrail.settings.CONFIG_PATH", deep)
        save_settings(Settings())
        assert deep.exists()

    def test_engagement_credentials_persist(self, config_dir):
        s = Settings()
        eng = s.create_engagement("cred-test")
        eng.add_credential(StoredCredential(username="admin", value="secret", validated=True))
        s.set_engagement(eng)
        save_settings(s)

        loaded = load_settings()
        eng2 = loaded.get_engagement("cred-test")
        cred = eng2.get_credential("admin")
        assert cred.value == "secret"
        assert cred.validated is True


# =============================================================================
# Settings — get_effective_config (merge priority)
# =============================================================================

class TestEffectiveConfig:
    def test_defaults_without_config(self, config_dir, monkeypatch):
        monkeypatch.delenv("NEO4J_PASSWORD", raising=False)
        cfg = get_effective_config()
        assert cfg["neo4j_uri"] == "bolt://localhost:7687"
        assert cfg["dc_ip"] == ""
        assert cfg["output_limit"] == 50

    def test_engagement_overrides_defaults(self, sample_settings):
        cfg = get_effective_config()
        assert cfg["dc_ip"] == "10.10.10.161"
        assert cfg["domain"] == "htb.local"
        assert cfg["lhost"] == "10.10.14.5"

    def test_cli_args_override_engagement(self, sample_settings):
        args = Namespace(dc_ip="9.9.9.9", domain=None, domain_sid=None,
                         lhost=None, lport=None, uri=None, user=None,
                         neo4j_password=None, limit=None)
        cfg = get_effective_config(args)
        assert cfg["dc_ip"] == "9.9.9.9"
        assert cfg["domain"] == "htb.local"  # from engagement

    def test_cli_uri_overrides_all(self, sample_settings):
        args = Namespace(uri="bolt://override:7687", user="custom",
                         neo4j_password="secret", dc_ip=None, domain=None,
                         domain_sid=None, lhost=None, lport=None, limit=None)
        cfg = get_effective_config(args)
        assert cfg["neo4j_uri"] == "bolt://override:7687"
        assert cfg["neo4j_user"] == "custom"
        assert cfg["neo4j_password"] == "secret"

    def test_env_password_used_as_fallback(self, config_dir, monkeypatch):
        monkeypatch.setenv("NEO4J_PASSWORD", "env-pass")
        cfg = get_effective_config()
        assert cfg["neo4j_password"] == "env-pass"

    def test_limit_from_args(self, config_dir):
        args = Namespace(limit=100, dc_ip=None, domain=None, domain_sid=None,
                         lhost=None, lport=None, uri=None, user=None,
                         neo4j_password=None)
        cfg = get_effective_config(args)
        assert cfg["output_limit"] == 100


# =============================================================================
# CLI Routing — _is_subcommand
# =============================================================================

class TestSubcommandDetection:
    def test_known_subcommands(self):
        for cmd in ("enum", "import", "query", "pwn", "config", "doctor",
                    "spray", "creds", "analyze", "wizard", "ui",
                    "quickwin", "ingest", "escalate", "policy"):
            assert _is_subcommand(cmd), f"{cmd} should be a subcommand"

    def test_flags_are_not_subcommands(self):
        for flag in ("--list-queries", "--pwn", "-r", "--help", "-v"):
            assert not _is_subcommand(flag)

    def test_paths_are_not_subcommands(self):
        assert not _is_subcommand("/path/to/data")
        assert not _is_subcommand("./sharphound.zip")

    def test_unknown_words_are_not_subcommands(self):
        assert not _is_subcommand("foobar")
        assert not _is_subcommand("10.10.10.161")


# =============================================================================
# CLI Routing — main() dispatch
# =============================================================================

class TestMainRouting:
    def test_subcommand_routes_to_new_router(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["bloodtrail", "doctor"])
        with patch("bloodtrail.cli._run_subcommand", return_value=0) as mock:
            main()
            mock.assert_called_once()

    def test_flag_routes_to_legacy(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["bloodtrail", "--list-queries"])
        with patch("bloodtrail.cli._run_legacy", return_value=0) as mock:
            main()
            mock.assert_called_once()

    def test_no_args_routes_to_legacy(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["bloodtrail"])
        with patch("bloodtrail.cli._run_legacy", return_value=0) as mock:
            main()
            mock.assert_called_once()

    def test_positional_path_routes_to_legacy(self, monkeypatch, tmp_path):
        data_dir = tmp_path / "bhdata"
        data_dir.mkdir()
        monkeypatch.setattr(sys, "argv", ["bloodtrail", str(data_dir)])
        with patch("bloodtrail.cli._run_legacy", return_value=0) as mock:
            main()
            mock.assert_called_once()


# =============================================================================
# Subcommand Parser — structure
# =============================================================================

class TestSubcommandParser:
    def test_parser_creates_without_error(self):
        p = create_subcommand_parser()
        assert p is not None

    def test_all_subcommands_registered(self):
        p = create_subcommand_parser()
        # Parse each subcommand with --help should not crash (test by checking actions)
        assert p._subparsers is not None

    def test_enum_parses_target(self):
        p = create_subcommand_parser()
        args = p.parse_args(["enum", "10.10.10.161"])
        assert args.subcommand == "enum"
        assert args.target == "10.10.10.161"

    def test_import_parses_path(self):
        p = create_subcommand_parser()
        args = p.parse_args(["import", "/tmp/data.zip"])
        assert args.subcommand == "import"
        assert args.path == Path("/tmp/data.zip")

    def test_query_list(self):
        p = create_subcommand_parser()
        args = p.parse_args(["query", "list"])
        assert args.subcommand == "query"
        assert args.query_action == "list"

    def test_query_run_with_id(self):
        p = create_subcommand_parser()
        args = p.parse_args(["query", "run", "find-asrep"])
        assert args.query_action == "run"
        assert args.query_id == "find-asrep"

    def test_query_run_with_var(self):
        p = create_subcommand_parser()
        args = p.parse_args(["query", "run", "find-user", "--var", "USER=PETE@CORP.COM"])
        assert args.var == ["USER=PETE@CORP.COM"]

    def test_query_search(self):
        p = create_subcommand_parser()
        args = p.parse_args(["query", "search", "kerberos"])
        assert args.query_action == "search"
        assert args.keyword == "kerberos"

    def test_pwn_mark(self):
        p = create_subcommand_parser()
        args = p.parse_args(["pwn", "mark", "PETE@CORP.COM", "--cred-type", "password"])
        assert args.pwn_action == "mark"
        assert args.user == "PETE@CORP.COM"
        assert args.cred_type == "password"

    def test_pwn_list(self):
        p = create_subcommand_parser()
        args = p.parse_args(["pwn", "list"])
        assert args.pwn_action == "list"

    def test_config_show(self):
        p = create_subcommand_parser()
        args = p.parse_args(["config", "show"])
        assert args.config_action == "show"

    def test_config_set(self):
        p = create_subcommand_parser()
        args = p.parse_args(["config", "set", "dc-ip", "10.10.10.1"])
        assert args.config_action == "set"
        assert args.key == "dc-ip"
        assert args.value == "10.10.10.1"

    def test_config_new_engagement(self):
        p = create_subcommand_parser()
        args = p.parse_args(["config", "new", "htb-box", "--dc-ip", "1.2.3.4"])
        assert args.config_action == "new"
        assert args.name == "htb-box"
        assert args.dc_ip == "1.2.3.4"

    def test_config_use(self):
        p = create_subcommand_parser()
        args = p.parse_args(["config", "use", "htb-forest"])
        assert args.config_action == "use"
        assert args.name == "htb-forest"

    def test_spray_auto_with_tool(self):
        p = create_subcommand_parser()
        args = p.parse_args(["spray", "auto", "--tool", "kerbrute", "--execute"])
        assert args.spray_action == "auto"
        assert args.tool == "kerbrute"
        assert args.execute is True

    def test_creds_inline(self):
        p = create_subcommand_parser()
        args = p.parse_args(["creds", "admin:password123"])
        assert args.credential == "admin:password123"

    def test_creds_as_stored_user(self):
        p = create_subcommand_parser()
        args = p.parse_args(["creds", "--as", "svc-alfresco"])
        assert args.as_user == "svc-alfresco"

    def test_creds_stages(self):
        p = create_subcommand_parser()
        args = p.parse_args(["creds", "user:pass", "--stages", "validate,collect"])
        assert args.stages == "validate,collect"

    def test_analyze_detect(self):
        p = create_subcommand_parser()
        args = p.parse_args(["analyze", "detect"])
        assert args.analyze_action == "detect"

    def test_analyze_smb(self):
        p = create_subcommand_parser()
        args = p.parse_args(["analyze", "smb", "10.10.10.1", "-u", "admin", "-p", "pass"])
        assert args.analyze_action == "smb"
        assert args.host == "10.10.10.1"

    def test_analyze_chains(self):
        p = create_subcommand_parser()
        args = p.parse_args(["analyze", "chains", "svc-alfresco", "-d", "htb.local"])
        assert args.analyze_action == "chains"
        assert args.user == "svc-alfresco"
        assert args.domain == "htb.local"

    def test_policy_set_file(self):
        p = create_subcommand_parser()
        args = p.parse_args(["policy", "set", "policy.txt"])
        assert args.policy_action == "set"
        assert args.file == "policy.txt"

    def test_wizard_with_target(self):
        p = create_subcommand_parser()
        args = p.parse_args(["wizard", "10.10.10.161"])
        assert args.subcommand == "wizard"
        assert args.target == "10.10.10.161"

    def test_ui_with_port(self):
        p = create_subcommand_parser()
        args = p.parse_args(["ui", "--port", "9999"])
        assert args.port == 9999

    def test_doctor_parses(self):
        p = create_subcommand_parser()
        args = p.parse_args(["doctor"])
        assert args.subcommand == "doctor"
        assert hasattr(args, "_handler")

    def test_quickwin_parses(self):
        p = create_subcommand_parser()
        args = p.parse_args(["quickwin", "10.10.10.161", "-u", "admin", "-p", "pass"])
        assert args.subcommand == "quickwin"
        assert args.target == "10.10.10.161"

    def test_ingest_parses(self):
        p = create_subcommand_parser()
        args = p.parse_args(["ingest", "/tmp/data.zip", "--preset", "all"])
        assert args.subcommand == "ingest"
        assert args.preset == "all"

    def test_escalate_parses(self):
        p = create_subcommand_parser()
        args = p.parse_args(["escalate", "USER@DOMAIN", "--cred-type", "ntlm-hash"])
        assert args.subcommand == "escalate"
        assert args.user == "USER@DOMAIN"
        assert args.cred_type == "ntlm-hash"

    def test_global_opts_on_subcommand(self):
        p = create_subcommand_parser()
        args = p.parse_args(["query", "list", "--uri", "bolt://custom:7687", "-v"])
        assert args.uri == "bolt://custom:7687"
        assert args.verbose == 1


# =============================================================================
# Subcommand Handlers — _apply_settings_defaults
# =============================================================================

class TestApplySettingsDefaults:
    def test_fills_neo4j_from_config(self, sample_settings):
        args = Namespace(uri=None, user=None, neo4j_password=None,
                         dc_ip=None, domain=None)
        args = _apply_settings_defaults(args)
        assert args.uri == "bolt://10.10.10.1:7687"
        assert args.user == "neo4j"
        assert args.dc_ip == "10.10.10.161"
        assert args.domain == "htb.local"

    def test_cli_args_not_overwritten(self, sample_settings):
        args = Namespace(uri="bolt://mine:7687", user="custom",
                         neo4j_password="mypass", dc_ip="9.9.9.9", domain=None)
        args = _apply_settings_defaults(args)
        assert args.uri == "bolt://mine:7687"
        assert args.dc_ip == "9.9.9.9"
        assert args.domain == "htb.local"  # filled from engagement


# =============================================================================
# Config Handlers — engagement CRUD
# =============================================================================

class TestEngagementHandlers:
    def test_config_new_creates_engagement(self, config_dir, capsys):
        args = Namespace(
            config_action="new", name="new-box",
            dc_ip="1.2.3.4", domain="test.local",
            uri=None, user=None, neo4j_password=None,
            debug=None, verbose=0, quiet=False, limit=None,
            yes=False, subcommand="config",
        )
        result = _handle_config(args)
        assert result == 0
        s = load_settings()
        assert "new-box" in s.engagements
        assert s.active_engagement == "new-box"
        eng = s.get_engagement("new-box")
        assert eng.dc_ip == "1.2.3.4"

    def test_config_use_switches(self, sample_settings, capsys):
        args = Namespace(
            config_action="use", name="pg-practice",
            uri=None, user=None, neo4j_password=None,
            debug=None, verbose=0, quiet=False, limit=None,
            yes=False, subcommand="config",
        )
        result = _handle_config(args)
        assert result == 0
        s = load_settings()
        assert s.active_engagement == "pg-practice"

    def test_config_use_missing_fails(self, config_dir, capsys):
        args = Namespace(
            config_action="use", name="nonexistent",
            uri=None, user=None, neo4j_password=None,
            debug=None, verbose=0, quiet=False, limit=None,
            yes=False, subcommand="config",
        )
        result = _handle_config(args)
        assert result == 1

    def test_config_engagements_lists(self, sample_settings, capsys):
        args = Namespace(
            config_action="engagements",
            uri=None, user=None, neo4j_password=None,
            debug=None, verbose=0, quiet=False, limit=None,
            yes=False, subcommand="config",
        )
        result = _handle_config(args)
        assert result == 0
        out = capsys.readouterr().out
        assert "htb-forest" in out
        assert "pg-practice" in out
        assert "*" in out  # active marker

    def test_config_set_stores_value(self, sample_settings, capsys):
        args = Namespace(
            config_action="set", key="lport", value="8443",
            uri=None, user=None, neo4j_password=None,
            debug=None, verbose=0, quiet=False, limit=None,
            yes=False, subcommand="config",
        )
        result = _handle_config(args)
        assert result == 0
        s = load_settings()
        eng = s.get_engagement("htb-forest")
        assert eng.lport == 8443


# =============================================================================
# Pager — truncate_results
# =============================================================================

class TestPager:
    def test_no_truncation_under_limit(self):
        data = list(range(10))
        result, total, truncated = truncate_results(data, limit=50)
        assert result == data
        assert total == 10
        assert truncated is False

    def test_truncation_at_limit(self):
        data = list(range(100))
        result, total, truncated = truncate_results(data, limit=25)
        assert len(result) == 25
        assert total == 100
        assert truncated is True

    def test_zero_limit_no_truncation(self):
        data = list(range(100))
        result, total, truncated = truncate_results(data, limit=0)
        assert result == data
        assert truncated is False

    def test_exact_limit(self):
        data = list(range(50))
        result, total, truncated = truncate_results(data, limit=50)
        assert result == data
        assert truncated is False

    def test_empty_list(self):
        result, total, truncated = truncate_results([], limit=50)
        assert result == []
        assert total == 0
        assert truncated is False

    def test_paged_output_noop_when_not_tty(self):
        """paged_output should be a no-op when stdout is not a TTY."""
        with paged_output(enabled=True):
            pass  # Should not crash

    def test_paged_output_disabled(self):
        with paged_output(enabled=False):
            pass  # Should not crash


# =============================================================================
# Doctor — command structure
# =============================================================================

class TestDoctor:
    def test_doctor_imports(self):
        from bloodtrail.cli.commands.doctor import DoctorCommands, TOOLS
        assert len(TOOLS) > 0
        assert hasattr(DoctorCommands, "handle")

    def test_doctor_check_tools(self):
        from bloodtrail.cli.commands.doctor import DoctorCommands
        # _check_tools always returns 0 (tools are optional)
        result = DoctorCommands._check_tools()
        assert result == 0

    def test_doctor_check_python_deps(self):
        from bloodtrail.cli.commands.doctor import DoctorCommands
        # Core deps (neo4j, requests, bs4) should be installed
        result = DoctorCommands._check_python_deps()
        assert result == 0

    def test_doctor_check_config_without_file(self, config_dir):
        from bloodtrail.cli.commands.doctor import DoctorCommands
        result = DoctorCommands._check_config()
        assert result == 0  # Warning, not error


# =============================================================================
# Legacy Backward Compatibility
# =============================================================================

class TestLegacyCompat:
    def test_create_parser_still_works(self):
        from bloodtrail.cli import create_parser
        p = create_parser()
        assert p is not None

    def test_command_groups_still_exported(self):
        from bloodtrail.cli import COMMAND_GROUPS
        assert len(COMMAND_GROUPS) == 11

    def test_legacy_parser_has_new_flags(self):
        from bloodtrail.cli import create_parser
        p = create_parser()
        args = p.parse_args(["--limit", "100", "--no-pager"])
        assert args.limit == 100
        assert args.no_pager is True

    def test_legacy_flags_parse(self):
        from bloodtrail.cli import create_parser
        p = create_parser()
        args = p.parse_args(["--list-queries"])
        assert args.list_queries is True

    def test_legacy_run_query_flag(self):
        from bloodtrail.cli import create_parser
        p = create_parser()
        args = p.parse_args(["--run-query", "find-asrep", "--var", "X=Y"])
        assert args.run_query == "find-asrep"
        assert args.var == ["X=Y"]


# =============================================================================
# XDG Path Compliance
# =============================================================================

class TestXDGPaths:
    def test_respects_xdg_config_home(self, monkeypatch, tmp_path):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        from bloodtrail.settings import _config_dir
        assert _config_dir() == tmp_path / "bloodtrail"

    def test_respects_xdg_data_home(self, monkeypatch, tmp_path):
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        from bloodtrail.settings import _data_dir
        assert _data_dir() == tmp_path / "bloodtrail"

    def test_defaults_to_dot_config(self, monkeypatch):
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        from bloodtrail.settings import _config_dir
        assert ".config/bloodtrail" in str(_config_dir())


# =============================================================================
# Credential Store — via handlers
# =============================================================================

class TestCredentialStore:
    def test_creds_as_flag_pulls_from_store(self, sample_settings):
        """--as svc-alfresco should pull the stored credential."""
        args = Namespace(
            as_user="svc-alfresco", credential=None, creds=None,
            creds_file=None, use_potfile=False,
            uri=None, user=None, neo4j_password=None,
            dc_ip=None, domain=None, debug=None, verbose=0,
            quiet=False, limit=None,
        )
        from bloodtrail.cli.app import _handle_creds
        with patch("bloodtrail.cli.commands.creds.CredsCommands.handle", return_value=0) as mock:
            _handle_creds(args)
            called_args = mock.call_args[0][0]
            assert "svc-alfresco" in called_args.creds
            assert "s3rvice" in called_args.creds

    def test_creds_as_flag_missing_user_fails(self, sample_settings, capsys):
        args = Namespace(
            as_user="nobody", credential=None, creds=None,
            creds_file=None, use_potfile=False,
            uri=None, user=None, neo4j_password=None,
            dc_ip=None, domain=None, debug=None, verbose=0,
            quiet=False, limit=None,
        )
        from bloodtrail.cli.app import _handle_creds
        result = _handle_creds(args)
        assert result == 1

    def test_inline_credential_passed_through(self, config_dir):
        args = Namespace(
            as_user=None, credential="admin:pass123", creds=None,
            creds_file=None, use_potfile=False,
            uri=None, user=None, neo4j_password=None,
            dc_ip=None, domain=None, debug=None, verbose=0,
            quiet=False, limit=None,
        )
        from bloodtrail.cli.app import _handle_creds
        with patch("bloodtrail.cli.commands.creds.CredsCommands.handle", return_value=0) as mock:
            _handle_creds(args)
            called_args = mock.call_args[0][0]
            assert called_args.creds == "admin:pass123"


# =============================================================================
# Query Handler — action mapping
# =============================================================================

class TestQueryHandler:
    def test_query_list_sets_flag(self, config_dir):
        args = Namespace(
            query_action="list", category=None,
            uri=None, user=None, neo4j_password=None,
            dc_ip=None, domain=None, debug=None, verbose=0,
            quiet=False, limit=None,
        )
        with patch("bloodtrail.cli.commands.query.QueryCommands.handle", return_value=0) as mock:
            _handle_query(args)
            called = mock.call_args[0][0]
            assert called.list_queries is True

    def test_query_run_sets_id(self, config_dir):
        args = Namespace(
            query_action="run", query_id="find-asrep",
            var=None, output_format="table",
            uri=None, user=None, neo4j_password=None,
            dc_ip=None, domain=None, debug=None, verbose=0,
            quiet=False, limit=None,
        )
        with patch("bloodtrail.cli.commands.query.QueryCommands.handle", return_value=0) as mock:
            _handle_query(args)
            called = mock.call_args[0][0]
            assert called.run_query == "find-asrep"

    def test_query_no_action_shows_usage(self, config_dir, capsys):
        args = Namespace(
            query_action=None,
            uri=None, user=None, neo4j_password=None,
            dc_ip=None, domain=None, debug=None, verbose=0,
            quiet=False, limit=None,
        )
        result = _handle_query(args)
        assert result == 1
        assert "Usage" in capsys.readouterr().out


# =============================================================================
# Subcommand Set — completeness
# =============================================================================

class TestSubcommandCompleteness:
    def test_all_expected_subcommands_exist(self):
        expected = {
            "enum", "import", "query", "pwn", "config", "policy",
            "spray", "creds", "analyze", "wizard", "ui", "doctor",
            "quickwin", "ingest", "escalate",
        }
        assert SUBCOMMANDS == expected

    def test_every_subcommand_has_handler(self):
        p = create_subcommand_parser()
        for cmd in SUBCOMMANDS:
            try:
                args = p.parse_args([cmd])
                assert hasattr(args, "_handler"), f"{cmd} missing _handler"
            except SystemExit:
                # Subcommands that require positional args will exit — that's fine,
                # the parser itself is wired correctly
                pass


# =============================================================================
# Handler Dispatch — all _handle_* functions via mocked command classes
# =============================================================================

class TestHandlerEnum:
    def test_enum_delegates_to_enumerate(self, config_dir):
        from bloodtrail.cli.app import _handle_enum
        args = Namespace(
            target="10.10.10.161", creds=None, creds_file=None, use_potfile=False,
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        with patch("bloodtrail.cli.commands.enumerate.EnumerateCommands.handle", return_value=0) as mock:
            _handle_enum(args)
            mock.assert_called_once()
            assert args.bh_data_dir == Path("10.10.10.161")

    def test_enum_with_creds_delegates_to_creds(self, config_dir):
        from bloodtrail.cli.app import _handle_enum
        args = Namespace(
            target="10.10.10.161", creds="admin:pass", creds_file=None, use_potfile=False,
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        with patch("bloodtrail.cli.commands.creds.CredsCommands.handle", return_value=0) as mock:
            _handle_enum(args)
            mock.assert_called_once()


class TestHandlerImport:
    def test_import_delegates(self, config_dir):
        from bloodtrail.cli.app import _handle_import
        args = Namespace(
            path=Path("/tmp/data.zip"), validate=False,
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        with patch("bloodtrail.cli.commands.import_data.ImportDataCommands.handle", return_value=0) as mock:
            _handle_import(args)
            mock.assert_called_once()
            assert args.bh_data_dir == Path("/tmp/data.zip")
            assert args.resume is False
            assert args.list_edges is False


class TestHandlerPwn:
    def test_pwn_no_action_shows_usage(self, config_dir, capsys):
        from bloodtrail.cli.app import _handle_pwn
        args = Namespace(
            pwn_action=None,
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        result = _handle_pwn(args)
        assert result == 1
        assert "Usage" in capsys.readouterr().out

    def test_pwn_mark_sets_flag(self, config_dir):
        from bloodtrail.cli.app import _handle_pwn
        args = Namespace(
            pwn_action="mark", user="PETE@CORP.COM", notes="test",
            cred_type="password", cred_value="pass",
            source_machine=None,
            uri=None, user_=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        # Rename 'user_' back — avoid conflict with argparse 'user'
        args.user = "PETE@CORP.COM"
        with patch("bloodtrail.cli.commands.pwned.PwnedCommands.handle", return_value=0) as mock:
            _handle_pwn(args)
            called = mock.call_args[0][0]
            assert called.pwn == "PETE@CORP.COM"

    def test_pwn_list_sets_flag(self, config_dir):
        from bloodtrail.cli.app import _handle_pwn
        args = Namespace(
            pwn_action="list",
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        with patch("bloodtrail.cli.commands.pwned.PwnedCommands.handle", return_value=0) as mock:
            _handle_pwn(args)
            called = mock.call_args[0][0]
            assert called.list_pwned is True

    def test_pwn_all_actions_set_flags(self, config_dir):
        from bloodtrail.cli.app import _handle_pwn
        action_flag = {
            "targets": "cred_targets",
            "post-exploit": "post_exploit",
            "recommend": "recommend",
            "ips": "list_ip_addresses",
            "interactive": "pwn_interactive",
        }
        for action, flag in action_flag.items():
            args = Namespace(
                pwn_action=action,
                uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
                debug=None, verbose=0, quiet=False, limit=None,
            )
            with patch("bloodtrail.cli.commands.pwned.PwnedCommands.handle", return_value=0) as mock:
                _handle_pwn(args)
                called = mock.call_args[0][0]
                assert getattr(called, flag) is True, f"{action} should set {flag}"


class TestHandlerPolicy:
    def test_policy_no_action_shows_usage(self, config_dir, capsys):
        from bloodtrail.cli.app import _handle_policy
        args = Namespace(
            policy_action=None,
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        result = _handle_policy(args)
        assert result == 1

    def test_policy_show_sets_flag(self, config_dir):
        from bloodtrail.cli.app import _handle_policy
        args = Namespace(
            policy_action="show",
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        with patch("bloodtrail.cli.commands.policy.PolicyCommands.handle", return_value=0) as mock:
            _handle_policy(args)
            called = mock.call_args[0][0]
            assert called.show_policy is True

    def test_policy_set_passes_file(self, config_dir):
        from bloodtrail.cli.app import _handle_policy
        args = Namespace(
            policy_action="set", file="policy.txt",
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        with patch("bloodtrail.cli.commands.policy.PolicyCommands.handle", return_value=0) as mock:
            _handle_policy(args)
            called = mock.call_args[0][0]
            assert called.set_policy == "policy.txt"

    def test_policy_clear_sets_flag(self, config_dir):
        from bloodtrail.cli.app import _handle_policy
        args = Namespace(
            policy_action="clear",
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        with patch("bloodtrail.cli.commands.policy.PolicyCommands.handle", return_value=0) as mock:
            _handle_policy(args)
            called = mock.call_args[0][0]
            assert called.clear_policy is True


class TestHandlerSpray:
    def test_spray_no_action_shows_usage(self, config_dir, capsys):
        from bloodtrail.cli.app import _handle_spray
        args = Namespace(
            spray_action=None,
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        result = _handle_spray(args)
        assert result == 1

    def test_spray_show_sets_flag(self, config_dir):
        from bloodtrail.cli.app import _handle_spray
        args = Namespace(
            spray_action="show", spray_method="all",
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        with patch("bloodtrail.cli.commands.spray.SprayCommands.handle", return_value=0) as mock:
            _handle_spray(args)
            called = mock.call_args[0][0]
            assert called.spray is True

    def test_spray_tailored_sets_flag(self, config_dir):
        from bloodtrail.cli.app import _handle_spray
        args = Namespace(
            spray_action="tailored", output=None,
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        with patch("bloodtrail.cli.commands.spray.SprayCommands.handle", return_value=0) as mock:
            _handle_spray(args)
            called = mock.call_args[0][0]
            assert called.spray_tailored is True

    def test_spray_auto_sets_flags(self, config_dir):
        from bloodtrail.cli.app import _handle_spray
        args = Namespace(
            spray_action="auto", tool="kerbrute", execute=True,
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        with patch("bloodtrail.cli.commands.spray.SprayCommands.handle", return_value=0) as mock:
            _handle_spray(args)
            called = mock.call_args[0][0]
            assert called.auto_spray is True
            assert called.spray_tool == "kerbrute"


class TestHandlerAnalyze:
    def test_analyze_no_action_shows_usage(self, config_dir, capsys):
        from bloodtrail.cli.app import _handle_analyze
        args = Namespace(
            analyze_action=None,
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        result = _handle_analyze(args)
        assert result == 1

    def test_analyze_detect_sets_flag(self, config_dir):
        from bloodtrail.cli.app import _handle_analyze
        args = Namespace(
            analyze_action="detect",
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        with patch("bloodtrail.cli.commands.analyze.AnalyzeCommands.handle", return_value=0) as mock:
            _handle_analyze(args)
            called = mock.call_args[0][0]
            assert called.detect is True

    def test_analyze_smb_sets_host_and_share(self, config_dir):
        from bloodtrail.cli.app import _handle_analyze
        args = Namespace(
            analyze_action="smb", host="10.10.10.1", share="Data",
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        with patch("bloodtrail.cli.commands.analyze.AnalyzeCommands.handle", return_value=0) as mock:
            _handle_analyze(args)
            called = mock.call_args[0][0]
            assert called.crawl_smb == "10.10.10.1"
            assert called.share == "Data"

    def test_analyze_chains_sets_user_and_domain(self, config_dir):
        from bloodtrail.cli.app import _handle_analyze
        args = Namespace(
            analyze_action="chains", user="svc-alfresco", domain="htb.local",
            dc_ip="10.10.10.161",
            uri=None, neo4j_password=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        with patch("bloodtrail.cli.commands.analyze.AnalyzeCommands.handle", return_value=0) as mock:
            _handle_analyze(args)
            called = mock.call_args[0][0]
            assert called.chains == "svc-alfresco"

    def test_analyze_sqlite_sets_target(self, config_dir):
        from bloodtrail.cli.app import _handle_analyze
        args = Namespace(
            analyze_action="sqlite", db_file="/tmp/db.sqlite", target="10.10.10.1",
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        with patch("bloodtrail.cli.commands.analyze.AnalyzeCommands.handle", return_value=0) as mock:
            _handle_analyze(args)
            called = mock.call_args[0][0]
            assert called.hunt_sqlite == "/tmp/db.sqlite"
            assert called.target == "10.10.10.1"

    def test_analyze_services_sets_flag(self, config_dir):
        from bloodtrail.cli.app import _handle_analyze
        args = Namespace(
            analyze_action="services",
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        with patch("bloodtrail.cli.commands.analyze.AnalyzeCommands.handle", return_value=0) as mock:
            _handle_analyze(args)
            called = mock.call_args[0][0]
            assert called.analyze_svc is True

    def test_analyze_reuse_passes_file(self, config_dir):
        from bloodtrail.cli.app import _handle_analyze
        args = Namespace(
            analyze_action="reuse", creds_file="creds.txt",
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        with patch("bloodtrail.cli.commands.analyze.AnalyzeCommands.handle", return_value=0) as mock:
            _handle_analyze(args)
            called = mock.call_args[0][0]
            assert called.analyze_reuse == "creds.txt"

    def test_analyze_dotnet_passes_file(self, config_dir):
        from bloodtrail.cli.app import _handle_analyze
        args = Namespace(
            analyze_action="dotnet", file="/tmp/app.exe",
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        with patch("bloodtrail.cli.commands.analyze.AnalyzeCommands.handle", return_value=0) as mock:
            _handle_analyze(args)
            called = mock.call_args[0][0]
            assert called.hunt_dotnet == "/tmp/app.exe"

    def test_analyze_deleted_passes_file(self, config_dir):
        from bloodtrail.cli.app import _handle_analyze
        args = Namespace(
            analyze_action="deleted", ldif_file="/tmp/deleted.ldif",
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        with patch("bloodtrail.cli.commands.analyze.AnalyzeCommands.handle", return_value=0) as mock:
            _handle_analyze(args)
            called = mock.call_args[0][0]
            assert called.parse_deleted == "/tmp/deleted.ldif"


class TestHandlerWizard:
    def test_wizard_fresh_sets_flag(self, config_dir):
        from bloodtrail.cli.app import _handle_wizard
        args = Namespace(
            target="10.10.10.161", resume=None,
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        with patch("bloodtrail.cli.commands.wizard.WizardCommands.handle", return_value=0) as mock:
            _handle_wizard(args)
            called = mock.call_args[0][0]
            assert called.wizard is True
            assert called.wizard_target == "10.10.10.161"

    def test_wizard_resume_sets_flag(self, config_dir):
        from bloodtrail.cli.app import _handle_wizard
        args = Namespace(
            target=None, resume="10.10.10.161",
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        with patch("bloodtrail.cli.commands.wizard.WizardCommands.handle", return_value=0) as mock:
            _handle_wizard(args)
            called = mock.call_args[0][0]
            assert called.wizard_resume == "10.10.10.161"


class TestHandlerUI:
    def test_ui_sets_flags(self, config_dir):
        from bloodtrail.cli.app import _handle_ui
        args = Namespace(
            path=Path("/tmp/data"), port=9999,
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        with patch("bloodtrail.cli.commands.ui.UICommands.handle", return_value=0) as mock:
            _handle_ui(args)
            called = mock.call_args[0][0]
            assert called.ui is True
            assert called.bh_data_dir == Path("/tmp/data")


class TestHandlerDoctor:
    def test_doctor_delegates(self, config_dir):
        from bloodtrail.cli.app import _handle_doctor
        args = Namespace(
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        with patch("bloodtrail.cli.commands.doctor.DoctorCommands.handle", return_value=0) as mock:
            _handle_doctor(args)
            mock.assert_called_once()


# =============================================================================
# Compound Workflow Handlers
# =============================================================================

class TestHandlerQuickwin:
    def test_quickwin_calls_enum_then_queries(self, config_dir):
        from bloodtrail.cli.app import _handle_quickwin
        args = Namespace(
            target="10.10.10.161", ad_username=None, ad_password=None, domain=None,
            uri=None, user=None, neo4j_password=None, dc_ip=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        with patch("bloodtrail.cli.commands.enumerate.EnumerateCommands.handle", return_value=-1), \
             patch("bloodtrail.cli.commands.query.QueryCommands.handle", return_value=0) as q_mock:
            result = _handle_quickwin(args)
            assert q_mock.call_count >= 2  # roast queries + run-all
            assert result == 0

    def test_quickwin_stops_on_enum_failure(self, config_dir):
        from bloodtrail.cli.app import _handle_quickwin
        args = Namespace(
            target="10.10.10.161", ad_username=None, ad_password=None, domain=None,
            uri=None, user=None, neo4j_password=None, dc_ip=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        with patch("bloodtrail.cli.commands.enumerate.EnumerateCommands.handle", return_value=1):
            result = _handle_quickwin(args)
            assert result == 1


class TestHandlerIngest:
    def test_ingest_calls_import_then_queries(self, config_dir):
        from bloodtrail.cli.app import _handle_ingest
        args = Namespace(
            path=Path("/tmp/data.zip"), preset="attack-paths", report_path=None,
            batch_size=500,
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        with patch("bloodtrail.cli.commands.import_data.ImportDataCommands.handle", return_value=0), \
             patch("bloodtrail.cli.commands.query.QueryCommands.handle", return_value=0) as q_mock:
            result = _handle_ingest(args)
            q_mock.assert_called_once()
            assert result == 0

    def test_ingest_stops_on_import_failure(self, config_dir):
        from bloodtrail.cli.app import _handle_ingest
        args = Namespace(
            path=Path("/tmp/data.zip"), preset="attack-paths", report_path=None,
            batch_size=500,
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        with patch("bloodtrail.cli.commands.import_data.ImportDataCommands.handle", return_value=1):
            result = _handle_ingest(args)
            assert result == 1


class TestHandlerEscalate:
    def test_escalate_calls_pwn_recommend_postexploit(self, config_dir):
        from bloodtrail.cli.app import _handle_escalate
        args = Namespace(
            user="ADMIN@CORP.COM", cred_type="password", cred_value=None,
            uri=None, user_=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        args.user = "ADMIN@CORP.COM"
        with patch("bloodtrail.cli.commands.pwned.PwnedCommands.handle", return_value=0) as mock:
            result = _handle_escalate(args)
            assert mock.call_count == 3  # pwn + recommend + post-exploit

    def test_escalate_stores_credential(self, sample_settings):
        from bloodtrail.cli.app import _handle_escalate
        args = Namespace(
            user="admin@htb.local", cred_type="password", cred_value="secret123",
            uri=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
        )
        with patch("bloodtrail.cli.commands.pwned.PwnedCommands.handle", return_value=0):
            _handle_escalate(args)
        s = load_settings()
        eng = s.get_engagement("htb-forest")
        cred = eng.get_credential("admin")
        assert cred is not None
        assert cred.value == "secret123"
        assert cred.domain == "htb.local"


# =============================================================================
# Config Handler — additional paths
# =============================================================================

class TestConfigSetAdditional:
    def test_set_neo4j_uri(self, config_dir):
        from bloodtrail.cli.app import _handle_config
        args = Namespace(
            config_action="set", key="neo4j-uri", value="bolt://custom:7687",
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None, yes=False,
            subcommand="config",
        )
        result = _handle_config(args)
        assert result == 0
        s = load_settings()
        assert s.neo4j_uri == "bolt://custom:7687"

    def test_set_neo4j_user(self, config_dir):
        from bloodtrail.cli.app import _handle_config
        args = Namespace(
            config_action="set", key="neo4j-user", value="admin",
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None, yes=False,
            subcommand="config",
        )
        result = _handle_config(args)
        assert result == 0
        s = load_settings()
        assert s.neo4j_user == "admin"

    def test_set_creates_default_engagement(self, config_dir):
        from bloodtrail.cli.app import _handle_config
        args = Namespace(
            config_action="set", key="dc-ip", value="1.2.3.4",
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None, yes=False,
            subcommand="config",
        )
        result = _handle_config(args)
        assert result == 0
        s = load_settings()
        assert "default" in s.engagements

    def test_config_no_action_shows_usage(self, config_dir, capsys):
        from bloodtrail.cli.app import _handle_config
        args = Namespace(
            config_action=None,
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None, yes=False,
            subcommand="config",
        )
        result = _handle_config(args)
        assert result == 1

    def test_config_show_delegates(self, config_dir):
        from bloodtrail.cli.app import _handle_config
        args = Namespace(
            config_action="show",
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None, yes=False,
            subcommand="config",
        )
        with patch("bloodtrail.cli.commands.config.ConfigCommands.handle", return_value=0) as mock:
            _handle_config(args)
            called = mock.call_args[0][0]
            assert called.show_config is True

    def test_config_purge_delegates(self, config_dir):
        from bloodtrail.cli.app import _handle_config
        args = Namespace(
            config_action="purge", yes=True,
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None,
            subcommand="config",
        )
        with patch("bloodtrail.cli.commands.config.ConfigCommands.handle", return_value=0) as mock:
            _handle_config(args)
            called = mock.call_args[0][0]
            assert called.purge is True

    def test_empty_engagements_message(self, config_dir, capsys):
        from bloodtrail.cli.app import _handle_config
        args = Namespace(
            config_action="engagements",
            uri=None, user=None, neo4j_password=None, dc_ip=None, domain=None,
            debug=None, verbose=0, quiet=False, limit=None, yes=False,
            subcommand="config",
        )
        result = _handle_config(args)
        assert result == 0
        assert "No engagements" in capsys.readouterr().out


# =============================================================================
# Settings — engagement neo4j override paths
# =============================================================================

class TestEngagementNeo4jOverride:
    def test_engagement_neo4j_uri_overrides_global(self, config_dir):
        s = Settings(neo4j_uri="bolt://global:7687")
        eng = s.create_engagement("box")
        eng.neo4j_uri = "bolt://custom:7687"
        s.set_engagement(eng)
        save_settings(s)
        cfg = get_effective_config()
        assert cfg["neo4j_uri"] == "bolt://custom:7687"

    def test_engagement_neo4j_user_overrides_global(self, config_dir):
        s = Settings(neo4j_user="global_user")
        eng = s.create_engagement("box")
        eng.neo4j_user = "custom_user"
        s.set_engagement(eng)
        save_settings(s)
        cfg = get_effective_config()
        assert cfg["neo4j_user"] == "custom_user"


# =============================================================================
# Full CLI Routing — _run_subcommand and _run_legacy internals
# =============================================================================

class TestRunSubcommand:
    def test_run_subcommand_calls_handler(self, monkeypatch, config_dir):
        monkeypatch.setattr(sys, "argv", ["bloodtrail", "doctor"])
        mock_handler = MagicMock(return_value=0)
        with patch("bloodtrail.cli.app._handle_doctor", mock_handler):
            from bloodtrail.cli import _run_subcommand
            result = _run_subcommand()
            assert result == 0
            mock_handler.assert_called_once()

    def test_run_subcommand_no_handler_shows_help(self, monkeypatch, config_dir, capsys):
        monkeypatch.setattr(sys, "argv", ["bloodtrail", "config"])
        from bloodtrail.cli import _run_subcommand
        result = _run_subcommand()
        # With no sub-action, _handle_config prints usage and returns 1
        assert result == 1

    def test_run_legacy_with_flag(self, monkeypatch, config_dir):
        monkeypatch.setattr(sys, "argv", ["bloodtrail", "--list-queries"])
        with patch("bloodtrail.cli.commands.query.QueryCommands.handle", return_value=0) as mock:
            from bloodtrail.cli import _run_legacy
            result = _run_legacy()
            assert result == 0
            mock.assert_called_once()


# =============================================================================
# Input Mode Detection — legacy parser utility
# =============================================================================

class TestDetectInputMode:
    def test_ip_returns_enumerate(self):
        from bloodtrail.cli.parser import detect_input_mode, InputMode
        mode, val = detect_input_mode("10.10.10.161")
        assert mode == InputMode.ENUMERATE
        assert val == "10.10.10.161"

    def test_hostname_returns_enumerate(self):
        from bloodtrail.cli.parser import detect_input_mode, InputMode
        mode, val = detect_input_mode("dc.corp.local")
        assert mode == InputMode.ENUMERATE

    def test_directory_returns_bloodhound(self, tmp_path):
        from bloodtrail.cli.parser import detect_input_mode, InputMode
        mode, val = detect_input_mode(str(tmp_path))
        assert mode == InputMode.BLOODHOUND

    def test_zip_returns_bloodhound(self, tmp_path):
        from bloodtrail.cli.parser import detect_input_mode, InputMode
        z = tmp_path / "data.zip"
        z.touch()
        mode, val = detect_input_mode(str(z))
        assert mode == InputMode.BLOODHOUND

    def test_invalid_raises(self):
        from bloodtrail.cli.parser import detect_input_mode
        with pytest.raises(ValueError):
            detect_input_mode("notathing")
