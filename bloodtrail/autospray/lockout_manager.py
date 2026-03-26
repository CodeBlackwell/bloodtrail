"""
Lockout Manager for Auto Password Spray

Enforces safe spray timing based on AD password policy to prevent
account lockouts during password spraying operations.

Features:
- Policy-aware attempt calculation (threshold - safety margin)
- Automatic delay enforcement between spray rounds
- Override mode for lab environments
- Spray plan generation for timing display
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Optional, Callable, Tuple
import time
import math


@dataclass
class SprayWindow:
    """
    Represents a safe spray window (one round of spraying).

    Attributes:
        round_number: Which spray round (1-indexed)
        passwords: Passwords to spray in this round
        max_attempts: Maximum attempts allowed
        delay_seconds: Seconds to wait after this round
        start_time: When this round started (filled at runtime)
        end_time: When this round ended (filled at runtime)
    """
    round_number: int
    passwords: List[str]
    max_attempts: int
    delay_seconds: int
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    @property
    def password_count(self) -> int:
        """Number of passwords in this round."""
        return len(self.passwords)

    def mark_started(self) -> None:
        """Mark round as started."""
        self.start_time = datetime.now()

    def mark_completed(self) -> None:
        """Mark round as completed."""
        self.end_time = datetime.now()


@dataclass
class LockoutManager:
    """
    Manages spray timing to prevent account lockouts.

    Uses AD password policy to calculate:
    - Safe attempts per window (threshold - safety_margin)
    - Required delay between spray rounds (observation_window)

    Attributes:
        policy: PasswordPolicy from policy_parser (optional)
        safety_margin: Buffer below threshold (default: 2)
        override_mode: Bypass all lockout protection (lab only)
        manual_threshold: Override threshold if policy unavailable
        manual_window_minutes: Override observation window
    """
    policy: Optional[object] = None  # PasswordPolicy
    safety_margin: int = 2
    override_mode: bool = False
    manual_threshold: Optional[int] = None
    manual_window_minutes: Optional[int] = None

    # Internal tracking
    _spray_history: List[datetime] = field(default_factory=list)
    _current_round: int = 0
    _last_spray_time: Optional[datetime] = None

    @property
    def lockout_threshold(self) -> int:
        """Get lockout threshold from policy or manual override."""
        if self.manual_threshold is not None:
            return self.manual_threshold
        if self.policy and hasattr(self.policy, 'lockout_threshold'):
            return self.policy.lockout_threshold
        return 0  # Unknown - no lockout or not configured

    @property
    def observation_window_minutes(self) -> int:
        """Get observation window in minutes."""
        if self.manual_window_minutes is not None:
            return self.manual_window_minutes
        if self.policy and hasattr(self.policy, 'observation_window'):
            return self.policy.observation_window
        return 30  # Conservative default

    @property
    def safe_attempts(self) -> int:
        """
        Calculate safe number of attempts per observation window.

        Returns threshold - safety_margin, with minimum of 1.
        Returns 999 if no lockout policy or override mode.
        """
        if self.override_mode:
            return 999  # No limit

        threshold = self.lockout_threshold
        if threshold == 0:
            return 999  # No lockout policy configured

        return max(1, threshold - self.safety_margin)

    @property
    def delay_seconds(self) -> int:
        """Required delay between spray rounds in seconds."""
        if self.override_mode:
            return 0

        return self.observation_window_minutes * 60

    @property
    def has_policy(self) -> bool:
        """Check if a lockout policy is configured."""
        return self.lockout_threshold > 0

    def can_spray(self) -> Tuple[bool, int]:
        """
        Check if we can spray now.

        Returns:
            Tuple of (can_spray: bool, wait_seconds: int)
            wait_seconds is 0 if can_spray is True
        """
        if self.override_mode:
            return (True, 0)

        if not self._last_spray_time:
            return (True, 0)

        elapsed = (datetime.now() - self._last_spray_time).total_seconds()
        remaining = self.delay_seconds - elapsed

        if remaining <= 0:
            return (True, 0)

        return (False, int(remaining))

    def record_spray_round(self) -> None:
        """Record that a spray round was completed."""
        self._last_spray_time = datetime.now()
        self._current_round += 1
        self._spray_history.append(self._last_spray_time)

    def wait_for_window(
        self,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> None:
        """
        Block until next safe spray window.

        Args:
            progress_callback: Called with (remaining_seconds, total_seconds)
                              for progress display
        """
        can_spray, wait_seconds = self.can_spray()

        if can_spray:
            return

        total_wait = wait_seconds

        while wait_seconds > 0:
            if progress_callback:
                progress_callback(wait_seconds, total_wait)

            # Sleep in 1-second intervals for responsive progress updates
            time.sleep(1)
            wait_seconds -= 1

        # Final callback with 0 remaining
        if progress_callback:
            progress_callback(0, total_wait)

    def get_spray_plan(
        self,
        passwords: List[str],
        user_count: int = 1
    ) -> List[SprayWindow]:
        """
        Generate a spray plan showing timing.

        Creates SprayWindow objects for each round, distributing passwords
        across rounds based on safe_attempts.

        Args:
            passwords: List of passwords to spray
            user_count: Number of users (for display, doesn't affect rounds)

        Returns:
            List of SprayWindow objects representing the spray plan
        """
        if not passwords:
            return []

        windows: List[SprayWindow] = []
        safe = self.safe_attempts

        # Split passwords into chunks of safe_attempts size
        for i in range(0, len(passwords), safe):
            chunk = passwords[i:i + safe]
            round_num = (i // safe) + 1

            # Last round doesn't need delay
            is_last = (i + safe) >= len(passwords)

            windows.append(SprayWindow(
                round_number=round_num,
                passwords=chunk,
                max_attempts=safe,
                delay_seconds=0 if is_last else self.delay_seconds,
            ))

        return windows

    def get_estimated_duration(self, password_count: int) -> timedelta:
        """
        Estimate total spray duration.

        Args:
            password_count: Total number of passwords to spray

        Returns:
            timedelta with estimated duration
        """
        if self.override_mode or password_count == 0:
            return timedelta(seconds=0)

        safe = self.safe_attempts
        rounds = math.ceil(password_count / safe)

        # Delays only between rounds (not after last)
        delay_rounds = max(0, rounds - 1)
        total_delay_seconds = delay_rounds * self.delay_seconds

        # Add ~30 seconds per round for actual spraying (rough estimate)
        spray_time_seconds = rounds * 30

        return timedelta(seconds=total_delay_seconds + spray_time_seconds)

    def format_plan_display(
        self,
        passwords: List[str],
        user_count: int
    ) -> str:
        """
        Format spray plan for terminal display.

        Args:
            passwords: Passwords to spray
            user_count: Number of target users

        Returns:
            Formatted string for display
        """
        plan = self.get_spray_plan(passwords, user_count)

        if not plan:
            return "No passwords to spray."

        lines = [
            "Spray Plan",
            "=" * 50,
            f"  Total passwords:    {len(passwords)}",
            f"  Target users:       {user_count}",
            f"  Lockout threshold:  {self.lockout_threshold}" +
                (" (no lockout)" if self.lockout_threshold == 0 else " attempts"),
            f"  Safe per round:     {self.safe_attempts}",
            f"  Delay between:      {self.observation_window_minutes} minutes",
            "",
            "Rounds:",
            "-" * 50,
        ]

        for window in plan:
            pwd_display = ", ".join(window.passwords[:3])
            if len(window.passwords) > 3:
                pwd_display += f", ... (+{len(window.passwords) - 3} more)"

            lines.append(f"  Round {window.round_number}: {window.password_count} password(s)")
            lines.append(f"    Passwords: {pwd_display}")

            if window.delay_seconds > 0:
                mins = window.delay_seconds // 60
                lines.append(f"    Then wait: {mins} minutes")
            lines.append("")

        # Estimated duration
        duration = self.get_estimated_duration(len(passwords))
        if duration.total_seconds() > 0:
            hours = int(duration.total_seconds() // 3600)
            mins = int((duration.total_seconds() % 3600) // 60)
            if hours > 0:
                lines.append(f"Estimated total time: ~{hours}h {mins}m")
            else:
                lines.append(f"Estimated total time: ~{mins} minutes")

        if self.override_mode:
            lines.append("")
            lines.append("WARNING: Lockout protection DISABLED (override mode)")

        return "\n".join(lines)

    def reset(self) -> None:
        """Reset spray history for a new operation."""
        self._spray_history.clear()
        self._current_round = 0
        self._last_spray_time = None
