"""
Tests for AttackState and DiscoveredCredential using synthetic CASCADE.LOCAL data.

Verifies credential lifecycle, state transitions, and data model behavior.
"""

import pytest
from bloodtrail.recommendation.models import (
    AttackState,
    Finding,
    FindingType,
    Credential,
    CredentialType,
    RecommendationPriority,
)
from bloodtrail.core.models import (
    DiscoveredCredential,
    SecretType,
    SourceType,
    Confidence,
)


class TestDiscoveredCredential:
    def test_upn_format(self, discovered_credentials):
        cred = discovered_credentials[0]  # r.thompson
        assert cred.upn == "R.THOMPSON@CASCADE.LOCAL"

    def test_sam_account_format(self, discovered_credentials):
        cred = discovered_credentials[0]
        assert cred.sam_account == "CASCADE\\r.thompson"

    def test_domain_uppercased(self):
        cred = DiscoveredCredential(
            username="test", secret="pass", domain="cascade.local",
        )
        assert cred.domain == "CASCADE.LOCAL"

    def test_to_creds_string(self, discovered_credentials):
        cred = discovered_credentials[0]
        result = cred.to_creds_string()
        assert "CASCADE/r.thompson:rY4n5eva" == result

    def test_mark_validated(self):
        cred = DiscoveredCredential(username="test", secret="pass")
        cred.mark_validated("smb")
        assert cred.validated is True
        assert cred.validation_method == "smb"
        assert cred.confidence == Confidence.CONFIRMED

    def test_hash_equality(self):
        a = DiscoveredCredential(username="test", secret="pass", domain="CORP.LOCAL")
        b = DiscoveredCredential(username="TEST", secret="pass", domain="corp.local")
        assert a == b
        assert hash(a) == hash(b)

    def test_hash_inequality_different_secret(self):
        a = DiscoveredCredential(username="test", secret="pass1")
        b = DiscoveredCredential(username="test", secret="pass2")
        assert a != b

    def test_repr_masks_secret(self, discovered_credentials):
        r = repr(discovered_credentials[0])
        assert "rY4n5eva" not in r  # Full secret should be masked
        assert "rY4n" in r  # First 4 chars shown

    def test_to_neo4j_props(self, discovered_credentials):
        props = discovered_credentials[0].to_neo4j_props()
        assert props["cred_type"] == "password"
        assert props["cred_source_type"] == "ldap"
        assert "cred_discovered_at" in props


class TestAttackStateLifecycle:
    """Test state transitions through a realistic attack flow."""

    def test_anonymous_start(self, attack_state):
        assert attack_state.current_access_level == "anonymous"
        assert attack_state.current_user is None

    def test_add_finding_stores(self, attack_state, ldap_password_finding):
        attack_state.add_finding(ldap_password_finding)
        assert ldap_password_finding.id in attack_state.findings

    def test_credential_elevates_access(self, attack_state):
        cred = Credential(
            id="cred_1", username="r.thompson",
            credential_type=CredentialType.PASSWORD,
            value="rY4n5eva", domain="CASCADE.LOCAL",
            validated=True, access_level="user",
        )
        attack_state.add_credential(cred)
        assert attack_state.current_access_level == "user"
        assert attack_state.current_user == "r.thompson"

    def test_admin_credential_elevates_to_admin(self, attack_state):
        cred = Credential(
            id="cred_admin", username="Administrator",
            credential_type=CredentialType.NTLM_HASH,
            value="aad3b435b51404ee:31d6cfe0d16ae931",
            domain="CASCADE.LOCAL",
            validated=True, access_level="admin",
        )
        attack_state.add_credential(cred)
        assert attack_state.current_access_level == "admin"

    def test_validated_credentials_filter(self, attack_state):
        valid = Credential(
            id="c1", username="user1",
            credential_type=CredentialType.PASSWORD,
            value="pass", validated=True,
        )
        unvalidated = Credential(
            id="c2", username="user2",
            credential_type=CredentialType.PASSWORD,
            value="maybe", validated=False,
        )
        attack_state.add_credential(valid)
        attack_state.add_credential(unvalidated)
        validated = attack_state.get_validated_credentials()
        assert len(validated) == 1
        assert validated[0].username == "user1"

    def test_full_attack_flow(self, attack_state):
        """Simulate: anonymous → find password → validate → user access."""
        # 1. Anonymous - discover LDAP attribute
        finding = Finding(
            id="f1", finding_type=FindingType.LDAP_ATTRIBUTE,
            source="ldap", target="cascadeLegacyPwd",
            raw_value="clk0bjVldmE=",
            decoded_value="rY4n5eva", decode_method="base64",
        )
        attack_state.add_finding(finding)
        assert attack_state.has_finding_type(FindingType.LDAP_ATTRIBUTE)

        # 2. Validate credential
        cred = Credential(
            id="c1", username="r.thompson",
            credential_type=CredentialType.PASSWORD,
            value="rY4n5eva", domain="CASCADE.LOCAL",
            validated=True, access_level="user",
            source_finding="f1",
        )
        attack_state.add_credential(cred)
        assert attack_state.current_access_level == "user"

        # 3. Find VNC file
        vnc = Finding(
            id="f2", finding_type=FindingType.FILE,
            source="smb_crawl", target="VNC Install.reg",
            raw_value="encrypted_hex",
        )
        attack_state.add_finding(vnc)
        assert len(attack_state.findings) == 2

        # 4. Second credential
        cred2 = Credential(
            id="c2", username="s.smith",
            credential_type=CredentialType.PASSWORD,
            value="sT333ve2", domain="CASCADE.LOCAL",
            validated=True, access_level="user",
        )
        attack_state.add_credential(cred2)
        assert len(attack_state.get_validated_credentials()) == 2
