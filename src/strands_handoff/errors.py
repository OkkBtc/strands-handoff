"""Domain errors exposed by strands-handoff."""


class HandoffError(Exception):
    """Base error for expected user-facing failures."""


class SessionFormatError(HandoffError):
    """The source is not a supported Strands session layout."""


class PackIntegrityError(HandoffError):
    """A strandpack is malformed or failed integrity verification."""
