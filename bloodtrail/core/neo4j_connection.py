"""
BloodTrail Neo4j Connection Manager

Provides a reusable connection context manager for Neo4j operations.
Extracted from query_runner.py to centralize connection management.
"""

from contextlib import contextmanager
from typing import Optional, Generator

from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, AuthError

from ..config import Neo4jConfig


class Neo4jConnection:
    """
    Managed Neo4j connection with context manager support.

    Example:
        conn = Neo4jConnection()
        if conn.connect():
            with conn.driver.session() as session:
                result = session.run("MATCH (n) RETURN count(n)")
            conn.close()

    Or as context manager:
        with get_neo4j_session() as session:
            result = session.run("MATCH (n) RETURN count(n)")
    """

    def __init__(self, config: Optional[Neo4jConfig] = None):
        """
        Initialize connection with optional config.

        Args:
            config: Neo4jConfig instance. If None, uses default config.
        """
        self.config = config or Neo4jConfig()
        self.driver = None
        self._connected = False

    def connect(self) -> bool:
        """
        Establish Neo4j connection.

        Returns:
            True if connection successful, False otherwise
        """
        try:
            self.driver = GraphDatabase.driver(
                self.config.uri,
                auth=(self.config.user, self.config.password)
            )
            # Test connection
            with self.driver.session() as session:
                session.run("RETURN 1")
            self._connected = True
            return True
        except AuthError:
            print(f"[!] Neo4j authentication failed (user: {self.config.user})")
            return False
        except ServiceUnavailable:
            print(f"[!] Neo4j not available at {self.config.uri}")
            return False
        except Exception as e:
            print(f"[!] Neo4j connection error: {e}")
            return False

    def close(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()
            self.driver = None
            self._connected = False

    @property
    def is_connected(self) -> bool:
        """Check if currently connected."""
        return self._connected and self.driver is not None

    def __enter__(self):
        """Context manager entry."""
        if not self._connected:
            self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
        return False  # Don't suppress exceptions


@contextmanager
def get_neo4j_session(
    config: Optional[Neo4jConfig] = None
) -> Generator:
    """
    Context manager for Neo4j session.

    Handles connection setup and teardown automatically.
    Raises ConnectionError if connection fails.

    Example:
        with get_neo4j_session() as session:
            result = session.run("MATCH (n:User) RETURN n.name LIMIT 10")
            for record in result:
                print(record["n.name"])

    Args:
        config: Optional Neo4jConfig. Uses defaults if not provided.

    Yields:
        Neo4j session object

    Raises:
        ConnectionError: If connection to Neo4j fails
    """
    conn = Neo4jConnection(config)
    if not conn.connect():
        raise ConnectionError(
            f"Failed to connect to Neo4j at {conn.config.uri}. "
            "Ensure Neo4j is running: sudo neo4j start"
        )
    try:
        with conn.driver.session() as session:
            yield session
    finally:
        conn.close()
