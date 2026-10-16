"""
C-DAC Role-Based Access Control (RBAC) Module

Defines system roles, permission hierarchies, and confidentiality clearance
rules for source code assets in compliance with C-DAC security guidelines.
"""
from typing import Set

# Canonical Roles
ROLE_CDAC_OFFICER = "cdac_officer"
ROLE_SECURITY_ANALYST = "security_analyst"
ROLE_USER = "user"

# Aliases for backwards compatibility and standard nomenclature
ROLE_ALIASES = {
    "admin": ROLE_CDAC_OFFICER,
    "officer": ROLE_CDAC_OFFICER,
    "cdac_admin": ROLE_CDAC_OFFICER,
    "analyst": ROLE_SECURITY_ANALYST,
    "auditor": ROLE_SECURITY_ANALYST,
    "security_officer": ROLE_CDAC_OFFICER,
    "viewer": ROLE_USER,
    "developer": ROLE_USER,
    "guest": ROLE_USER,
}

# Roles authorized to fetch, view, scan, and download confidential source code
SOURCE_CODE_AUTHORIZED_ROLES: Set[str] = {
    ROLE_CDAC_OFFICER,
    ROLE_SECURITY_ANALYST,
    "admin",
    "officer",
    "cdac_admin",
    "analyst",
    "auditor",
    "security_officer",
}

# Human-readable labels
ROLE_LABELS = {
    ROLE_CDAC_OFFICER: "C-DAC Security Officer",
    ROLE_SECURITY_ANALYST: "Security Analyst",
    ROLE_USER: "Standard User (Restricted)",
}


def normalize_role(role: str | None) -> str:
    """Normalizes role string to canonical form."""
    if not role:
        return ROLE_USER
    r = role.strip().lower()
    return ROLE_ALIASES.get(r, r)


def has_source_code_access(role: str | None) -> bool:
    """Checks whether the given role is cleared to access confidential source code."""
    if not role:
        return False
    normalized = normalize_role(role)
    return normalized in SOURCE_CODE_AUTHORIZED_ROLES


def get_role_label(role: str | None) -> str:
    """Returns a clean display label for UI representation."""
    normalized = normalize_role(role)
    return ROLE_LABELS.get(normalized, normalized.replace("_", " ").title())
