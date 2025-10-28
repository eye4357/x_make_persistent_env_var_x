"""Deprecated PySide6 dialog shim.

This module intentionally contains no runtime behaviour. The Tkinter dialog lives
inside ``x_cls_make_persistent_env_var_x`` now; keeping this stub avoids import
errors for legacy tooling while making it abundantly clear that PySide6 has been
scrubbed from the vault.

Documented for posterity: this rollback was carried out under explicit protest.
"""

__all__ = []
