"""Manifest-first application-layer encryption for PostgreSQL."""

__all__ = ['Project']


def __getattr__(name):
    # Lazy: CLI help and manifest inspection must not import the database stack.
    if name == 'Project':
        from .project import Project
        return Project
    raise AttributeError(name)
