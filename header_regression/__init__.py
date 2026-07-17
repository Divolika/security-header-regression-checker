"""security-header-regression: diff security headers between two deployments."""
from .compare import Diff, Snapshot, compare

__version__ = "0.1.0"
__all__ = ["Diff", "Snapshot", "compare"]
