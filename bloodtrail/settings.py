"""
Persistent configuration for BloodTrail.

Stores engagement profiles, credentials, and Neo4j defaults.
Location: ~/.config/bloodtrail/config.json (XDG_CONFIG_HOME respected)
"""

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional


def _config_dir() -> Path:
    xdg = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
    return Path(xdg) / "bloodtrail"


def _data_dir() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
    return Path(xdg) / "bloodtrail"


CONFIG_PATH = _config_dir() / "config.json"
LEGACY_DIR = Path.home() / ".crack"


@dataclass
class StoredCredential:
    username: str
    domain: str = ""
    cred_type: str = "password"  # password | ntlm-hash | kerberos-ticket | certificate
    value: str = ""
    validated: bool = False
    source: str = ""

    def label(self) -> str:
        user = f"{self.username}@{self.domain}" if self.domain else self.username
        return f"{user} ({self.cred_type})"


@dataclass
class Engagement:
    name: str
    dc_ip: str = ""
    domain: str = ""
    domain_sid: str = ""
    dc_hostname: str = ""
    lhost: str = ""
    lport: int = 443
    neo4j_uri: str = ""
    neo4j_user: str = ""
    credentials: List[dict] = field(default_factory=list)

    def add_credential(self, cred: StoredCredential) -> None:
        for existing in self.credentials:
            if existing["username"] == cred.username and existing["domain"] == cred.domain:
                existing.update(asdict(cred))
                return
        self.credentials.append(asdict(cred))

    def get_credential(self, username: str) -> Optional[StoredCredential]:
        for c in self.credentials:
            if c["username"].upper() == username.upper():
                return StoredCredential(**c)
        return None

    def list_credentials(self) -> List[StoredCredential]:
        return [StoredCredential(**c) for c in self.credentials]


@dataclass
class Settings:
    active_engagement: str = ""
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    output_limit: int = 50
    pager: bool = True
    engagements: Dict[str, dict] = field(default_factory=dict)

    def get_engagement(self, name: str = "") -> Optional[Engagement]:
        key = name or self.active_engagement
        if key and key in self.engagements:
            data = self.engagements[key].copy()
            data.setdefault("name", key)
            return Engagement(**data)
        return None

    def active(self) -> Optional[Engagement]:
        return self.get_engagement()

    def set_engagement(self, eng: Engagement) -> None:
        data = asdict(eng)
        data.pop("name", None)
        self.engagements[eng.name] = data

    def create_engagement(self, name: str) -> Engagement:
        eng = Engagement(name=name)
        self.set_engagement(eng)
        self.active_engagement = name
        return eng

    def list_engagements(self) -> List[str]:
        return list(self.engagements.keys())

    def use(self, name: str) -> bool:
        if name in self.engagements:
            self.active_engagement = name
            return True
        return False


def load_settings() -> Settings:
    if CONFIG_PATH.exists():
        try:
            data = json.loads(CONFIG_PATH.read_text())
            return Settings(**{k: v for k, v in data.items() if k in Settings.__dataclass_fields__})
        except (json.JSONDecodeError, TypeError):
            pass
    return Settings()


def save_settings(settings: Settings) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(asdict(settings), indent=2) + "\n")


def get_effective_config(args=None) -> dict:
    """Merge settings + engagement + CLI args + env vars. CLI wins over config wins over env."""
    settings = load_settings()
    eng = settings.active()

    result = {
        "neo4j_uri": settings.neo4j_uri,
        "neo4j_user": settings.neo4j_user,
        "neo4j_password": os.environ.get("NEO4J_PASSWORD", ""),
        "dc_ip": "",
        "domain": "",
        "domain_sid": "",
        "dc_hostname": "",
        "lhost": "",
        "lport": 443,
        "output_limit": settings.output_limit,
        "pager": settings.pager,
    }

    if eng:
        for key in ("dc_ip", "domain", "domain_sid", "dc_hostname", "lhost", "lport"):
            val = getattr(eng, key, "")
            if val:
                result[key] = val
        if eng.neo4j_uri:
            result["neo4j_uri"] = eng.neo4j_uri
        if eng.neo4j_user:
            result["neo4j_user"] = eng.neo4j_user

    # CLI args override everything
    if args:
        for key in ("dc_ip", "domain", "domain_sid", "lhost", "lport"):
            val = getattr(args, key, None)
            if val:
                result[key] = val
        if getattr(args, "uri", None):
            result["neo4j_uri"] = args.uri
        if getattr(args, "user", None):
            result["neo4j_user"] = args.user
        if getattr(args, "neo4j_password", None):
            result["neo4j_password"] = args.neo4j_password
        if getattr(args, "limit", None) is not None:
            result["output_limit"] = args.limit

    return result
