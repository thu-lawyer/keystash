"""keystash — local secret broker for API keys, tokens and passwords.

v0.4.0 stores values in the macOS login Keychain and keeps only metadata on
disk. There is no read tool: nothing this package exposes returns a secret.
"""

__version__ = "0.4.0"
