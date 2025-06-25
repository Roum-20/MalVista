import pefile, hashlib

def get_hashes(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
    return {
        "MD5": hashlib.md5(data).hexdigest(),
        "SHA1": hashlib.sha1(data).hexdigest(),
        "SHA256": hashlib.sha256(data).hexdigest(),
    }

def extract_strings(file_path):
    with open(file_path, 'rb') as f:
        content = f.read()
    return list(set([s.decode('utf-8', errors='ignore') for s in content.split(b'\x00') if len(s) > 4]))

def get_imports(file_path):
    try:
        pe = pefile.PE(file_path)
        imports = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode()
            funcs = [imp.name.decode() if imp.name else "None" for imp in entry.imports]
            imports.append((dll, funcs))
        return imports
    except Exception as e:
        return [("Error", [str(e)])]
