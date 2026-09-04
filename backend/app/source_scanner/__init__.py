"""
Source Code Security Analyzer (SAST) Package
Supports static analysis for Python, JavaScript/JSX, TypeScript/TSX, and Java.
"""

from app.source_scanner.scanner import scan_directory, scan_file

__all__ = ["scan_directory", "scan_file"]
