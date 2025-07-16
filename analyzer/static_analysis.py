import hashlib
import re

def perform_static_analysis(file_path):
    """
    Perform basic static analysis:
    - Compute file hashes (MD5, SHA256)
    - Extract printable strings
    """
    hashes = calculate_hashes(file_path)
    strings = extract_strings(file_path)
    return hashes, strings

def calculate_hashes(file_path):
    """
    Compute MD5 and SHA256 hashes of the file
    """
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha256.update(chunk)
    return {
        "md5": md5.hexdigest(),
        "sha256": sha256.hexdigest()
    }

def extract_strings(file_path):
    """
    Extract printable ASCII strings (length ≥ 5) from binary file
    """
    with open(file_path, "rb") as f:
        data = f.read()
    strings = re.findall(rb"[ -~]{5,}", data)
    return [s.decode(errors="ignore") for s in strings]
