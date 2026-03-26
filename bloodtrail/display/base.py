"""
Base utilities for bloodtrail display modules.

Provides shared color classes, helper functions, and utilities used across
all display modules.
"""

from typing import List


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


class NoColors:
    """Dummy colors class for non-colored output"""
    HEADER = ''
    BLUE = ''
    CYAN = ''
    GREEN = ''
    YELLOW = ''
    RED = ''
    MAGENTA = ''
    BOLD = ''
    DIM = ''
    RESET = ''


def truncate(s: str, max_len: int) -> str:
    """Truncate string with '..' indicator"""
    if len(s) > max_len:
        return s[:max_len-2] + ".."
    return s


def extract_creds_from_pwned_users(pwned_users: List) -> tuple:
    """
    Extract passwords and usernames from PwnedUser objects.

    Args:
        pwned_users: List of PwnedUser objects with credentials

    Returns:
        Tuple of (passwords: List[str], usernames: List[str])
    """
    passwords = []
    usernames = []
    for user in pwned_users or []:
        usernames.append(user.username)
        for ctype, cval in zip(user.cred_types, user.cred_values):
            if ctype == "password" and cval:
                passwords.append(cval)
    return passwords, usernames


def fill_spray_template(
    cmd: str,
    dc_ip: str,
    domain: str,
    password: str = "<PASSWORD>",
    usernames: List[str] = None,
) -> str:
    """
    Fill placeholders in a spray command template.

    Args:
        cmd: Command template with placeholders
        dc_ip: Domain Controller IP
        domain: Domain name
        password: Password to fill
        usernames: List of usernames (first one used for <USERNAME>)

    Returns:
        Command with placeholders replaced
    """
    result = cmd
    result = result.replace("<DC_IP>", dc_ip)
    result = result.replace("<DOMAIN>", domain.lower() if domain else "<DOMAIN>")
    result = result.replace("<PASSWORD>", password)
    result = result.replace("<USER_FILE>", "users.txt")
    result = result.replace("<PASSWORD_FILE>", "passwords.txt")
    if usernames:
        result = result.replace("<USERNAME>", usernames[0])
    return result


def get_colors(use_colors: bool = True):
    """Return appropriate Colors class based on flag."""
    return Colors if use_colors else NoColors


# Backward compatibility aliases
_NoColors = NoColors
_truncate = truncate
