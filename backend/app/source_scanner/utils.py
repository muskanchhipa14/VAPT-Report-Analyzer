import os
import shutil
import zipfile
from typing import List, Tuple, Optional

# Security Limits
MAX_EXTRACTED_FILES = 2000
MAX_UNCOMPRESSED_SIZE_BYTES = 150 * 1024 * 1024  # 150MB
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10MB individual file


class ZipSecurityError(Exception):
    pass


def safe_extract_zip(zip_path: str, destination_dir: str) -> List[str]:
    """
    Safely extracts a ZIP archive into destination_dir while preventing:
    1. Zip Slip (path traversal)
    2. Decompression bombs (file count and uncompressed size limits)
    3. Symlink / device attacks

    Returns list of absolute paths to extracted files.
    """
    if not zipfile.is_zipfile(zip_path):
        raise ZipSecurityError("Uploaded file is not a valid ZIP archive.")

    os.makedirs(destination_dir, exist_ok=True)
    destination_abs = os.path.abspath(destination_dir)

    extracted_files = []
    total_uncompressed_size = 0
    total_file_count = 0

    with zipfile.ZipFile(zip_path, "r") as zf:
        infolist = zf.infolist()

        for member in infolist:
            total_file_count += 1
            if total_file_count > MAX_EXTRACTED_FILES:
                raise ZipSecurityError(
                    f"Archive exceeds maximum allowable file count ({MAX_EXTRACTED_FILES} files)."
                )

            total_uncompressed_size += member.file_size
            if total_uncompressed_size > MAX_UNCOMPRESSED_SIZE_BYTES:
                raise ZipSecurityError(
                    f"Archive exceeds maximum uncompressed size limit ({MAX_UNCOMPRESSED_SIZE_BYTES // (1024 * 1024)}MB)."
                )

            if member.file_size > MAX_FILE_SIZE_BYTES:
                # Skip excessively large individual files
                continue

            # Zip Slip / Path Traversal Check
            member_path = member.filename
            # Normalize and combine
            target_path = os.path.abspath(os.path.join(destination_abs, member_path))

            # Must start with destination_abs + os.sep (or be destination_abs itself)
            if not (target_path == destination_abs or target_path.startswith(destination_abs + os.sep)):
                raise ZipSecurityError(f"Path traversal detected in ZIP entry: {member.filename}")

            # Check for symlinks in zip metadata
            is_symlink = (member.external_attr >> 16) & 0o120000 == 0o120000
            if is_symlink:
                # Reject or skip symlinks to avoid directory escapes
                continue

            if member.is_dir():
                os.makedirs(target_path, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                with zf.open(member) as source, open(target_path, "wb") as target:
                    shutil.copyfileobj(source, target)
                extracted_files.append(target_path)

    return extracted_files


def extract_code_snippet(
    lines: List[str],
    line_number: int,
    context_lines: int = 2
) -> str:
    """
    Extracts a formatted code snippet with surrounding context lines.
    Line numbers in output are 1-based.
    The vulnerable line is marked with '>'.
    """
    if not lines:
        return ""

    total_lines = len(lines)
    idx = line_number - 1  # 0-indexed

    start_idx = max(0, idx - context_lines)
    end_idx = min(total_lines, idx + context_lines + 1)

    snippet_parts = []
    for curr_idx in range(start_idx, end_idx):
        curr_line_no = curr_idx + 1
        marker = ">" if curr_line_no == line_number else " "
        line_content = lines[curr_idx].rstrip("\r\n")
        snippet_parts.append(f"{marker} {curr_line_no:4d} | {line_content}")

    return "\n".join(snippet_parts)


def cleanup_directory(directory_path: str):
    """Safely removes a temporary directory."""
    if directory_path and os.path.exists(directory_path):
        try:
            shutil.rmtree(directory_path, ignore_errors=True)
        except Exception:
            pass
