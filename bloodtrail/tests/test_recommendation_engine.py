"""
Tests for the BloodTrail recommendation engine.

Verifies the finding → trigger → recommendation pipeline using
synthetic CASCADE.LOCAL domain data from conftest.py.
"""

import pytest
from bloodtrail.recommendation.engine import RecommendationEngine
from bloodtrail.recommendation.models import (
    Finding,
    FindingType,
    Recommendation,
    RecommendationPriority,
    CredentialType,
)


class TestEngineInit:
    def test_creates_attack_state(self, recommendation_engine):
        assert recommendation_engine.state.target == "10.10.10.182"
        assert recommendation_engine.state.domain == "CASCADE.LOCAL"
        assert recommendation_engine.state.current_access_level == "anonymous"

    def test_starts_with_no_findings(self, recommendation_engine):
        assert len(recommendation_engine.state.findings) == 0
        assert recommendation_engine.state.get_next_recommendation() is None


class TestAddFinding:
    def test_stores_finding(self, recommendation_engine, ldap_password_finding):
        recommendation_engine.add_finding(ldap_password_finding)
        assert ldap_password_finding.id in recommendation_engine.state.findings

    def test_deduplicates_findings(self, recommendation_engine, ldap_password_finding):
        recs1 = recommendation_engine.add_finding(ldap_password_finding)
        recs2 = recommendation_engine.add_finding(ldap_password_finding)
        assert len(recs2) == 0  # Duplicate returns no new recommendations

    def test_ldap_password_triggers_recommendation(self, recommendation_engine, ldap_password_finding):
        recs = recommendation_engine.add_finding(ldap_password_finding)
        # Should generate at least one recommendation to test the credential
        assert len(recs) >= 1

    def test_asrep_finding_stored(self, recommendation_engine, asrep_finding):
        recommendation_engine.add_finding(asrep_finding)
        # AS-REP is stored even if no trigger rule matches (USER_FLAG type)
        assert asrep_finding.id in recommendation_engine.state.findings
        assert recommendation_engine.state.has_finding_type(FindingType.USER_FLAG)

    def test_vnc_file_triggers_decrypt(self, recommendation_engine, vnc_file_finding):
        recs = recommendation_engine.add_finding(vnc_file_finding)
        assert len(recs) >= 1
        # Should suggest decrypting or investigating VNC password
        descriptions = " ".join(r.description.lower() for r in recs)
        assert "vnc" in descriptions or "decrypt" in descriptions or "file" in descriptions


class TestRecommendationPriority:
    def test_critical_before_high(self, recommendation_engine):
        """CRITICAL recommendations should be served before HIGH."""
        high = Recommendation(
            id="high_rec", priority=RecommendationPriority.HIGH,
            trigger_finding_id="f1", action_type="run_command",
            description="High priority", why="test",
        )
        critical = Recommendation(
            id="critical_rec", priority=RecommendationPriority.CRITICAL,
            trigger_finding_id="f2", action_type="run_command",
            description="Critical priority", why="test",
        )
        recommendation_engine.state.add_recommendation(high)
        recommendation_engine.state.add_recommendation(critical)
        next_rec = recommendation_engine.state.get_next_recommendation()
        assert next_rec.id == "critical_rec"

    def test_priority_ordering(self, attack_state):
        """All priority levels should sort correctly."""
        for p in reversed(list(RecommendationPriority)):
            attack_state.add_recommendation(Recommendation(
                id=f"rec_{p.name}", priority=p,
                trigger_finding_id="f1", action_type="test",
                description=p.name, why="test",
            ))
        next_rec = attack_state.get_next_recommendation()
        assert next_rec.priority == RecommendationPriority.CRITICAL


class TestStateTracking:
    def test_complete_removes_from_pending(self, attack_state):
        rec = Recommendation(
            id="rec_1", priority=RecommendationPriority.HIGH,
            trigger_finding_id="f1", action_type="test",
            description="test", why="test",
        )
        attack_state.add_recommendation(rec)
        attack_state.complete_recommendation("rec_1")
        assert attack_state.get_next_recommendation() is None
        assert "rec_1" in attack_state.completed_actions

    def test_skip_removes_from_pending(self, attack_state):
        rec = Recommendation(
            id="rec_1", priority=RecommendationPriority.HIGH,
            trigger_finding_id="f1", action_type="test",
            description="test", why="test",
        )
        attack_state.add_recommendation(rec)
        attack_state.skip_recommendation("rec_1")
        assert attack_state.get_next_recommendation() is None
        assert "rec_1" in attack_state.skipped_actions

    def test_completed_not_re_added(self, attack_state):
        rec = Recommendation(
            id="rec_1", priority=RecommendationPriority.HIGH,
            trigger_finding_id="f1", action_type="test",
            description="test", why="test",
        )
        attack_state.add_recommendation(rec)
        attack_state.complete_recommendation("rec_1")
        attack_state.add_recommendation(rec)  # Try re-adding
        assert attack_state.get_next_recommendation() is None

    def test_invalidated_recommendation_not_added(self, attack_state):
        # Add a finding that invalidates the recommendation
        blocker = Finding(
            id="blocker_finding", finding_type=FindingType.CREDENTIAL,
            source="test", target="test", raw_value="x",
        )
        attack_state.add_finding(blocker)

        rec = Recommendation(
            id="rec_1", priority=RecommendationPriority.HIGH,
            trigger_finding_id="f1", action_type="test",
            description="test", why="test",
            invalidated_by=["blocker_finding"],
        )
        attack_state.add_recommendation(rec)
        assert attack_state.get_next_recommendation() is None

    def test_prerequisite_blocks_recommendation(self, attack_state):
        rec = Recommendation(
            id="rec_1", priority=RecommendationPriority.HIGH,
            trigger_finding_id="f1", action_type="test",
            description="test", why="test",
            requires=["missing_finding"],
        )
        attack_state.add_recommendation(rec)
        assert attack_state.get_next_recommendation() is None


class TestCredentialTracking:
    def test_add_credential(self, recommendation_engine):
        cred = recommendation_engine.add_credential(
            username="r.thompson", password="rY4n5eva",
            credential_type=CredentialType.PASSWORD,
            validated=True, access_level="user",
        )
        assert cred.username == "r.thompson"
        assert cred.validated is True
        assert recommendation_engine.state.current_access_level == "user"

    def test_validated_credential_creates_finding(self, recommendation_engine):
        recommendation_engine.add_credential(
            username="s.smith", password="sT333ve2",
            validated=True, access_level="user",
        )
        # Validated credentials generate a CREDENTIAL finding
        cred_findings = [
            f for f in recommendation_engine.state.findings.values()
            if f.finding_type == FindingType.CREDENTIAL
        ]
        assert len(cred_findings) >= 1

    def test_has_finding_type(self, attack_state, ldap_password_finding):
        attack_state.add_finding(ldap_password_finding)
        assert attack_state.has_finding_type(FindingType.LDAP_ATTRIBUTE)
        assert not attack_state.has_finding_type(FindingType.SERVICE)


class TestEndToEnd:
    def test_ldap_to_credential_flow(self, recommendation_engine, ldap_password_finding):
        """Full flow: LDAP finding → recommendation → credential."""
        recs = recommendation_engine.add_finding(ldap_password_finding)
        assert len(recs) >= 1

        # Complete the recommendation (simulating successful credential test)
        recommendation_engine.state.complete_recommendation(recs[0].id)

        # Add validated credential
        cred = recommendation_engine.add_credential(
            username="r.thompson", password="rY4n5eva",
            validated=True, access_level="user",
            source_finding=ldap_password_finding.id,
        )

        assert recommendation_engine.state.current_access_level == "user"
        assert len(recommendation_engine.state.get_validated_credentials()) == 1

    def test_multiple_findings_accumulate(self, recommendation_engine,
                                          ldap_password_finding, asrep_finding,
                                          vnc_file_finding):
        """Multiple findings should each produce recommendations."""
        all_recs = []
        for finding in [ldap_password_finding, asrep_finding, vnc_file_finding]:
            all_recs.extend(recommendation_engine.add_finding(finding))

        assert len(recommendation_engine.state.findings) == 3
        # LDAP and VNC have trigger rules, AS-REP (USER_FLAG) does not
        assert len(all_recs) >= 2
