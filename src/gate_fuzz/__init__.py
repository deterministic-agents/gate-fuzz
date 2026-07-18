"""gate-fuzz: cross-language differential property tests for GATE v1.4.

Pairs gate-python v1.2.0 against gate-rust v1.0.0. See PROTOCOL.md for
the line-delimited JSON wire contract between the Python harness and
the long-lived `gate-rust-cli` subprocess.
"""

__version__ = "1.0.0"
PROTOCOL_VERSION = "v1.0"
