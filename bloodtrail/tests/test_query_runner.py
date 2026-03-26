"""
Tests for query loading, variable substitution, and query execution.

Uses synthetic data from conftest.py and mocked Neo4j sessions.
"""

import pytest
from unittest.mock import MagicMock, patch
from bloodtrail.core.models import Query, QueryResult
from bloodtrail.core.query_loader import load_all_queries, get_queries_dir


class TestQueryModel:
    def test_has_variables(self, sample_query, sample_query_with_vars):
        assert sample_query.has_variables() is False
        assert sample_query_with_vars.has_variables() is True

    def test_get_required_variables(self, sample_query_with_vars):
        required = sample_query_with_vars.get_required_variables()
        assert "USER" in required

    def test_substitute_variables(self, sample_query_with_vars):
        result = sample_query_with_vars.substitute_variables(
            {"USER": "S.SMITH@CASCADE.LOCAL"}
        )
        assert "S.SMITH@CASCADE.LOCAL" in result
        assert "<USER>" not in result

    def test_substitute_preserves_unmatched(self, sample_query_with_vars):
        result = sample_query_with_vars.substitute_variables({"OTHER": "value"})
        assert "<USER>" in result  # Not substituted


class TestQueryLoader:
    def test_queries_dir_exists(self):
        assert get_queries_dir().exists()

    def test_load_all_queries(self):
        queries, categories = load_all_queries()
        assert len(queries) > 0
        assert len(categories) > 0

    def test_queries_have_required_fields(self):
        queries, _ = load_all_queries()
        for qid, q in queries.items():
            assert q.id == qid
            assert q.name
            assert q.cypher
            assert q.category

    def test_categories_reference_valid_queries(self):
        queries, categories = load_all_queries()
        for cat, query_ids in categories.items():
            for qid in query_ids:
                assert qid in queries, f"Category {cat} references missing query {qid}"

    def test_quick_wins_category_exists(self):
        _, categories = load_all_queries()
        assert "quick_wins" in categories


class TestQueryResult:
    def test_success_result(self):
        result = QueryResult(
            query_id="test", success=True,
            records=[{"name": "ADMIN@CASCADE.LOCAL"}],
            record_count=1,
        )
        assert result.success
        assert result.record_count == 1

    def test_error_result(self):
        result = QueryResult(
            query_id="test", success=False,
            error="Connection refused",
        )
        assert not result.success
        assert "Connection" in result.error


class TestMockedQueryExecution:
    """Test query execution using mocked Neo4j session from conftest."""

    def test_asrep_query(self, mock_neo4j_session, sample_query):
        result = mock_neo4j_session.run(sample_query.cypher)
        data = result.data()
        assert len(data) == 1
        assert data[0]["u.name"] == "SVC_BACKUP@CASCADE.LOCAL"

    def test_kerberoast_query(self, mock_neo4j_session):
        result = mock_neo4j_session.run(
            "MATCH (u:User) WHERE u.hasspn=true RETURN u.name, u.serviceprincipalnames"
        )
        data = result.data()
        assert len(data) == 2
        names = [r["u.name"] for r in data]
        assert "SVC_SQL@CASCADE.LOCAL" in names

    def test_admin_path_query(self, mock_neo4j_session):
        result = mock_neo4j_session.run(
            "MATCH (u:User)-[:AdminTo]->(c:Computer) RETURN u.name, c.name"
        )
        data = result.data()
        assert len(data) == 1
        assert data[0]["c.name"] == "DB01.CASCADE.LOCAL"

    def test_empty_result(self, mock_neo4j_session):
        result = mock_neo4j_session.run("MATCH (n:Nonexistent) RETURN n")
        assert len(result.data()) == 0
