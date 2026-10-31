try:
    from backend.schemas import Evidence, Finding, ModuleResult
except ImportError:
    from ._schemas_stub import Evidence, Finding, ModuleResult


__all__ = ["Evidence", "Finding", "ModuleResult"]