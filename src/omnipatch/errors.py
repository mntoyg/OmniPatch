"""OmniPatch exception hierarchy."""


class OmniPatchError(Exception):
    """Base for every OmniPatch failure."""


class ConfigError(OmniPatchError):
    """Invalid or missing configuration."""


class ScannerError(OmniPatchError):
    """Scanner execution or input failure."""


class PatchGenerationError(OmniPatchError):
    """Patch generation failure."""


class PatchApplyError(OmniPatchError):
    """Patch application failure."""


class VcsError(OmniPatchError):
    """Version control failure."""
