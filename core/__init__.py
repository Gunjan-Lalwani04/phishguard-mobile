"""Shared, UI-agnostic phishing detection core used by the mobile app.

Every analyzer here takes plain Python values (strings, tuples, lists) rather
than parsed-object models, so the same functions work whether the caller is
the Kivy UI, a CLI, or a test.
"""

__version__ = "0.1.0"
