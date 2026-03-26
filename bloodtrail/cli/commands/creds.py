"""
BloodTrail Creds Commands

Handles credential integration pipeline commands:
- --creds: Inline credential integration
- --creds-file: File-based credential integration
- --use-potfile: Potfile-based credential integration
"""

import os
from argparse import Namespace

from ..base import BaseCommandGroup
from ...config import Neo4jConfig
from ...creds_pipeline import CredentialPipeline, PipelineOptions


class CredsCommands(BaseCommandGroup):
    """Credential pipeline command handlers."""

    @classmethod
    def add_arguments(cls, parser) -> None:
        """Add creds arguments."""
        pass  # Arguments defined in cli/parser.py

    @classmethod
    def handle(cls, args: Namespace) -> int:
        """
        Handle credential pipeline commands.

        Returns:
            0 for success, non-zero for error, -1 if not handled
        """
        # Check if any creds options are set (but not during import mode)
        has_creds_opts = (
            getattr(args, 'creds', None) or
            getattr(args, 'creds_file', None) or
            getattr(args, 'use_potfile', False)
        )

        if has_creds_opts:
            return cls._handle_creds_mode(args)

        return -1

    @classmethod
    def _handle_creds_mode(cls, args: Namespace) -> int:
        """
        Handle --creds credential integration pipeline.

        Pipeline stages:
        1. Parse credentials from inline, file, or potfile
        2. Validate credentials (kerbrute/crackmapexec)
        3. Collect BloodHound data (bloodhound-python)
        4. Import to Neo4j
        5. Mark users as pwned
        6. Query and display attack paths
        """
        # Build pipeline options from args
        options = PipelineOptions(
            skip_validate=getattr(args, 'skip_validate', False),
            skip_collect=getattr(args, 'no_collect', False),
            skip_pwn=getattr(args, 'no_pwn', False),
            skip_import=getattr(args, 'no_import', False),
            output_dir=getattr(args, 'bh_output', None),
            verbose=getattr(args, 'verbose', 0),
            domain=getattr(args, 'domain', None),
        )

        # Neo4j config
        config = Neo4jConfig(uri=args.uri, user=args.user, password=getattr(args, "neo4j_password", None) or os.environ.get("NEO4J_PASSWORD", ""))

        # Target IP is required (from bh_data_dir positional arg)
        target = str(args.bh_data_dir) if getattr(args, 'bh_data_dir', None) else None
        if not target:
            cls.print_error("Target IP required when using --creds")
            print("    Usage: crack bloodtrail 10.10.10.161 --creds user:pass")
            return 1

        # Create and run pipeline
        pipeline = CredentialPipeline(target, config, options)

        result = pipeline.run(
            inline_creds=getattr(args, 'creds', None),
            creds_file=getattr(args, 'creds_file', None),
            use_potfile=getattr(args, 'use_potfile', False),
            potfile_path=getattr(args, 'potfile_path', None),
        )

        # Display summary
        print()
        if result.success:
            cls.print_success("Pipeline completed successfully")
            if result.credentials_valid:
                print(f"    Valid credentials: {result.credentials_valid}")
            if result.users_marked_pwned:
                print(f"    Users marked pwned: {result.users_marked_pwned}")
            if result.bloodhound_output_dir:
                print(f"    BloodHound data: {result.bloodhound_output_dir}")
        else:
            cls.print_error(f"Pipeline failed: {result.error}")

        return 0 if result.success else 1
