#!/usr/bin/env python3
# folder_converter.py
# Features: interactive menu, CLI, TXT/JSON export, AES-256-GCM encryption (optional), gzip (optional),
# glob ignore patterns, progress bar (tqdm).

import os
import sys
import io
import json
import gzip
import base64
import argparse
import fnmatch
import textwrap
from pathlib import Path
from getpass import getpass

# Optional deps
try:
    from tqdm import tqdm
except Exception:
    tqdm = None

try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False


# -------------------- Utils --------------------

def iter_files(root: Path, ignore_patterns):
    """Yield files (Path) under root, skipping any that match ignore_patterns (glob)."""
    ignore_patterns = ignore_patterns or []
    for dirpath, dirnames, filenames in os.walk(root):
        # Filter directories by patterns
        pruned_dirs = []
        for d in list(dirnames):
            full = Path(dirpath) / d
            if any(fnmatch.fnmatch(full.name, p) or fnmatch.fnmatch(str(full.relative_to(root)), p)
                   for p in ignore_patterns):
                continue
            pruned_dirs.append(d)
        dirnames[:] = pruned_dirs

        # Files
        for f in filenames:
            full = Path(dirpath) / f
            rel = full.relative_to(root)
            # Skip by patterns
            if any(fnmatch.fnmatch(f, p) or fnmatch.fnmatch(str(rel), p) for p in ignore_patterns):
                continue
            yield full


def read_file_bytes(p: Path) -> bytes:
    with open(p, 'rb') as f:
        return f.read()


def try_text_decode(b: bytes):
    """Return (is_text, text) for UTF-8 decoding without BOM."""
    try:
        return True, b.decode('utf-8')
    except UnicodeDecodeError:
        return False, None


def derive_key(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    """PBKDF2-HMAC-SHA256 -> 32-byte key for AES-256."""
    if not HAVE_CRYPTO:
        raise RuntimeError("cryptography is required for encryption. Install with: pip install cryptography")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(password.encode('utf-8'))


def encrypt_bytes(data: bytes, password: str):
    """Return dict with enc=True, nonce, salt, ciphertext (AES-256-GCM)."""
    salt = os.urandom(16)
    key = derive_key(password, salt)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, data, None)  # ciphertext || tag
    return {
        "enc": True,
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "data": ct
    }


def decrypt_bytes(enc_blob: dict, password: str) -> bytes:
    salt = base64.b64decode(enc_blob["salt"])
    nonce = base64.b64decode(enc_blob["nonce"])
    data = enc_blob["data"]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, data, None)


def maybe_gzip(data: bytes, do_compress: bool) -> (bytes, bool):
    if not do_compress:
        return data, False
    return gzip.compress(data), True


def maybe_gunzip(data: bytes, was_gzip: bool) -> bytes:
    return gzip.decompress(data) if was_gzip else data


def chunk_lines(s: str, width: int = 100):
    for i in range(0, len(s), width):
        yield s[i:i+width]


# -------------------- Export: JSON --------------------

def export_json(root: Path, out_file: Path, compress: bool, encrypt: bool,
                password: str | None, ignore_patterns, progress: bool):
    files = list(iter_files(root, ignore_patterns))
    bar = tqdm(total=len(files), desc="Exporting", unit="file") if progress and tqdm else None
    out = {
        "version": 1,
        "root_name": root.name,
        "files": []
    }

    for fp in files:
        rel = str(fp.relative_to(root)).replace("\\", "/")
        raw = read_file_bytes(fp)
        is_text, text = try_text_decode(raw)

        payload_bytes = raw if not is_text else text.encode('utf-8')

        payload_bytes, gz = maybe_gzip(payload_bytes, compress)

        if encrypt:
            enc_blob = encrypt_bytes(payload_bytes, password)
            data_b64 = base64.b64encode(enc_blob["data"]).decode()
            out["files"].append({
                "path": rel,
                "is_text_source": is_text,   # original heuristic (for user info; not required to restore)
                "gzip": gz,
                "encrypted": True,
                "salt": enc_blob["salt"],
                "nonce": enc_blob["nonce"],
                "data_b64": data_b64
            })
        else:
            data_b64 = base64.b64encode(payload_bytes).decode()
            out["files"].append({
                "path": rel,
                "is_text_source": is_text,
                "gzip": gz,
                "encrypted": False,
                "data_b64": data_b64
            })

        if bar: bar.update(1)

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

    if bar: bar.close()


# -------------------- Export: TXT (tree) --------------------

def export_txt(root: Path, out_file: Path, compress: bool, encrypt: bool,
               password: str | None, ignore_patterns, progress: bool):
    files = list(iter_files(root, ignore_patterns))
    # Build directory tree order: use os.walk to print directories in order
    all_entries = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Filter directories for output consistency (ignore patterns)
        dirnames[:] = [d for d in dirnames if not any(
            fnmatch.fnmatch(d, p) or fnmatch.fnmatch(str((Path(dirpath) / d).relative_to(root)), p)
            for p in (ignore_patterns or [])
        )]
        all_entries.append((Path(dirpath), sorted(filenames)))

    with open(out_file, "w", encoding="utf-8") as out:
        out.write(f"{root.name}\n")
        bar_total = sum(len(flist) for _, flist in all_entries)
        bar = tqdm(total=bar_total, desc="Exporting", unit="file") if progress and tqdm else None

        for dirpath, filenames in all_entries:
            level = len(dirpath.relative_to(root).parts)
            if level > 0:
                indent = "    " * (level - 1)
                out.write(f"{indent}├── {dirpath.name}\n")

            for fname in filenames:
                fp = dirpath / fname
                rel = fp.relative_to(root)
                # skip ignored (already filtered by iter_files, but ensure)
                if any(fnmatch.fnmatch(fname, p) or fnmatch.fnmatch(str(rel), p) for p in (ignore_patterns or [])):
                    continue

                indent_file = "    " * level
                out.write(f"{indent_file}├── {fname}\n")

                raw = read_file_bytes(fp)
                is_text, text = try_text_decode(raw)
                payload = raw if not is_text else text.encode('utf-8')

                payload, gz = maybe_gzip(payload, compress)

                if encrypt:
                    enc_blob = encrypt_bytes(payload, password)
                    data_b64 = base64.b64encode(enc_blob["data"]).decode()
                    header = f"{indent_file}│ [BASE64 DATA; ENC=AES256GCM; SALT={enc_blob['salt']}; NONCE={enc_blob['nonce']}; GZIP={'1' if gz else '0'}]\n"
                    out.write(header)
                    for line in chunk_lines(data_b64, 120):
                        out.write(f"{indent_file}│ {line}\n")
                else:
                    if is_text and not gz:
                        # Write raw text lines (readable)
                        out.write(f"{indent_file}│ [TEXT]\n")
                        text_stream = text.splitlines(keepends=True)
                        for line in text_stream:
                            out.write(f"{indent_file}│ {line}")
                    else:
                        # Write base64 data (binary or gzipped text)
                        data_b64 = base64.b64encode(payload).decode()
                        header = f"{indent_file}│ [BASE64 DATA; GZIP={'1' if gz else '0'}]\n"
                        out.write(header)
                        for line in chunk_lines(data_b64, 120):
                            out.write(f"{indent_file}│ {line}\n")

                if bar: bar.update(1)

        if bar: bar.close()


# -------------------- Import: JSON --------------------

def import_json(in_file: Path, out_folder: Path, progress: bool, password: str | None):
    with open(in_file, "r", encoding="utf-8") as f:
        doc = json.load(f)
    files = doc.get("files", [])
    bar = tqdm(total=len(files), desc="Importing", unit="file") if progress and tqdm else None

    for item in files:
        rel = item["path"]
        encrypted = item.get("encrypted", False)
        gz = item.get("gzip", False)
        data_b64 = item["data_b64"]
        b = base64.b64decode(data_b64)

        if encrypted:
            if password is None:
                # Prompt once for password if not provided
                password = getpass("Enter password to decrypt: ")
            blob = {"salt": item["salt"], "nonce": item["nonce"], "data": b, "enc": True}
            b = decrypt_bytes(blob, password)

        b = maybe_gunzip(b, gz)

        dest = out_folder / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "wb") as f:
            f.write(b)

        if bar: bar.update(1)

    if bar: bar.close()


# -------------------- Import: TXT --------------------

def parse_marker(line: str):
    """
    Parse markers like:
    [TEXT]
    [BASE64 DATA; GZIP=0]
    [BASE64 DATA; ENC=AES256GCM; SALT=...; NONCE=...; GZIP=1]
    Returns dict with keys: type ('TEXT' or 'B64'), gzip(bool), enc(bool), salt(str|None), nonce(str|None)
    """
    s = line.strip()
    if not (s.startswith("[") and s.endswith("]")):
        return None
    s = s[1:-1].strip()
    if s == "TEXT":
        return {"type": "TEXT", "gzip": False, "enc": False, "salt": None, "nonce": None}
    if s.startswith("BASE64"):
        meta = {"type": "B64", "gzip": False, "enc": False, "salt": None, "nonce": None}
        # Split by ';'
        parts = [p.strip() for p in s.split(";")]
        for p in parts[1:]:
            if p.upper().startswith("GZIP="):
                meta["gzip"] = p.split("=", 1)[1].strip() in ("1", "true", "True")
            elif p.upper().startswith("ENC="):
                val = p.split("=", 1)[1].strip().upper()
                if val in ("AES256GCM", "AES-256-GCM", "AESGCM"):
                    meta["enc"] = True
            elif p.upper().startswith("SALT="):
                meta["salt"] = p.split("=", 1)[1].strip()
            elif p.upper().startswith("NONCE="):
                meta["nonce"] = p.split("=", 1)[1].strip()
        return meta
    return None


def import_txt(in_file: Path, out_folder: Path, progress: bool, password: str | None):
    lines = Path(in_file).read_text(encoding="utf-8", errors="strict").splitlines()
    # We will reconstruct by scanning tree markers.
    # Maintain stack of folder paths by indent level.
    if not lines:
        return
    # first line is root name; ignore for destination (we already have out_folder)
    idx = 1
    stack = [out_folder]  # index == indent level + 1
    current_file = None
    header_meta = None
    collected = []

    # To drive a progress bar, first count files:
    file_count = sum(1 for ln in lines if ln.lstrip().startswith("├── ") and "." in ln.lstrip()[4:].strip())
    bar = tqdm(total=file_count, desc="Importing", unit="file") if progress and tqdm else None

    def flush_file():
        nonlocal current_file, header_meta, collected
        if current_file is None or header_meta is None:
            return
        dest = current_file
        dest.parent.mkdir(parents=True, exist_ok=True)
        if header_meta["type"] == "TEXT":
            # collected are raw text lines (already without the "│ ")
            data = "".join(collected).encode('utf-8')
        else:  # B64
            b64 = "".join(collected)
            data = base64.b64decode(b64)
            if header_meta.get("enc"):
                if password is None:
                    # Ask once if missing
                    pw = getpass("Enter password to decrypt: ")
                else:
                    pw = password
                blob = {"salt": header_meta.get("salt"), "nonce": header_meta.get("nonce"), "data": data, "enc": True}
                data = decrypt_bytes(blob, pw)
            data = maybe_gunzip(data, header_meta.get("gzip", False))

        with open(dest, "wb") as f:
            f.write(data)

    while idx < len(lines):
        raw = lines[idx]
        if not raw.strip():
            idx += 1
            continue

        # count leading spaces to determine indent level (4 spaces per level)
        stripped = raw.lstrip()
        spaces = len(raw) - len(stripped)
        level = spaces // 4

        if stripped.startswith("├── "):
            # New node (folder or file)
            # flush previous file if any
            if current_file is not None:
                flush_file()
                if bar: bar.update(1)
                current_file = None
                header_meta = None
                collected = []

            name = stripped[4:].strip()
            # Heuristic: consider entries with '.' as files, others as dirs (matches exporter)
            if "." in name:
                # file
                # stack index for parent = level
                parent = stack[level] if level < len(stack) else out_folder
                current_file = parent / name
            else:
                # directory
                # adjust stack
                parent = stack[level] if level < len(stack) else out_folder
                new_dir = parent / name
                new_dir.mkdir(parents=True, exist_ok=True)
                # ensure stack size
                if level + 1 < len(stack):
                    stack = stack[:level + 1]
                if level + 1 == len(stack):
                    stack.append(new_dir)
                else:
                    stack[level + 1] = new_dir

        elif stripped.startswith("│ "):
            content = stripped[2:]
            # First content line may be marker
            if header_meta is None:
                meta = parse_marker(content)
                if meta is not None:
                    header_meta = meta
                else:
                    # No explicit marker -> treat as TEXT and start collecting
                    header_meta = {"type": "TEXT", "gzip": False, "enc": False, "salt": None, "nonce": None}
                    collected.append(content if content.endswith("\n") else content + "\n")
            else:
                # Collect content lines
                if header_meta["type"] == "TEXT":
                    collected.append(content if content.endswith("\n") else content + "\n")
                else:
                    collected.append(content)

        else:
            # unrecognized line -> ignore safely
            pass

        idx += 1

    # flush last file
    if current_file is not None:
        flush_file()
        if bar: bar.update(1)

    if bar: bar.close()


# -------------------- Interactive Menu --------------------

def prompt_bool(q: str, default=False) -> bool:
    s = input(f"{q} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    if not s:
        return default
    return s in ("y", "yes")


def prompt_list(q: str) -> list[str]:
    s = input(f"{q} (space-separated, glob allowed; leave empty for none): ").strip()
    return s.split() if s else []


def interactive_menu():
    print("Folder <-> TXT/JSON Converter")
    print("------------------------------")
    print("1) Export folder")
    print("2) Import archive")
    print("3) Help")
    print("4) Exit")
    choice = input("Select an option: ").strip()

    if choice == "1":
        src = Path(input("Enter folder path to export: ").strip()).expanduser()
        if not src.is_dir():
            print("Invalid folder.")
            return
        fmt = input("Output format [txt/json] (default: txt): ").strip().lower() or "txt"
        dst = Path(input(f"Enter output file (e.g., backup.{fmt}): ").strip()).expanduser()
        compress = prompt_bool("Enable gzip compression for file payloads?", default=False)
        do_encrypt = prompt_bool("Enable AES-256-GCM password encryption for all files?", default=False)
        password = None
        if do_encrypt:
            if not HAVE_CRYPTO:
                print("Encryption requires 'cryptography'. Install with: pip install cryptography")
                return
            p1 = getpass("Enter password: ")
            p2 = getpass("Confirm password: ")
            if p1 != p2:
                print("Passwords do not match.")
                return
            password = p1
        ignore = prompt_list("Ignore patterns")
        show_progress = prompt_bool("Show progress bar?", default=True)

        if fmt not in ("txt", "json"):
            print("Invalid format.")
            return

        if fmt == "json":
            export_json(src, dst, compress, do_encrypt, password, ignore, show_progress)
        else:
            export_txt(src, dst, compress, do_encrypt, password, ignore, show_progress)
        print(f"Exported to {dst}")

    elif choice == "2":
        src = Path(input("Enter input file (.txt or .json): ").strip()).expanduser()
        if not src.is_file():
            print("Invalid file.")
            return
        dst = Path(input("Enter destination folder to rebuild: ").strip()).expanduser()
        dst.mkdir(parents=True, exist_ok=True)
        show_progress = prompt_bool("Show progress bar?", default=True)
        password = None  # will be asked only if needed

        if src.suffix.lower() == ".json":
            import_json(src, dst, show_progress, password)
        else:
            import_txt(src, dst, show_progress, password)
        print(f"Imported to {dst}")

    elif choice == "3":
        show_help()
    elif choice == "4":
        print("Goodbye!")
    else:
        print("Invalid option.")


# -------------------- CLI --------------------

def show_help():
    print(r"""
Folder <-> TXT/JSON Converter
--------------------------------
Modes:
  export   Export a folder to .txt (tree) or .json archive
  import   Import from .txt or .json and rebuild the folder

Export options:
  --format {txt,json}   Output format (default: txt)
  --compress            Gzip-compress file payloads before encoding/encryption
  --encrypt             AES-256-GCM encryption for all files (prompts for password)
  --ignore PATTERN ...  Glob patterns to ignore (e.g., __pycache__ .git *.log *secret*)
  --no-progress         Disable progress bar

Import options:
  --password PASS       Password (optional). If needed and not provided, you will be prompted.
  --no-progress         Disable progress bar

Examples:
  python folder_converter.py export /path/to/folder backup.txt --compress --ignore __pycache__ .git *.log
  python folder_converter.py export /path/to/folder backup.json --format json --encrypt
  python folder_converter.py import backup.txt /path/to/restore
  python folder_converter.py import backup.json /path/to/restore --password "MyStrongPass"
""")


def main():
    if len(sys.argv) == 1:
        interactive_menu()
        return
    if sys.argv[1].lower() in ("help", "-h", "--help"):
        show_help()
        return

    parser = argparse.ArgumentParser(description="Folder <-> TXT/JSON converter", add_help=False)
    parser.add_argument("mode", choices=["export", "import"], help="export or import")
    parser.add_argument("source", help="Source folder (export) or input file (import)")
    parser.add_argument("target", help="Target file (export) or destination folder (import)")

    # common toggles
    parser.add_argument("--no-progress", action="store_true", help="Disable progress bar")

    # export options
    parser.add_argument("--format", choices=["txt", "json"], default="txt", help="Export format (default: txt)")
    parser.add_argument("--compress", action="store_true", help="Gzip compress payloads")
    parser.add_argument("--encrypt", action="store_true", help="Encrypt all files with AES-256-GCM (prompts for password)")
    parser.add_argument("--ignore", nargs="*", default=[], help="Glob ignore patterns")

    # import options
    parser.add_argument("--password", default=None, help="Password for decryption (optional)")

    args = parser.parse_args()

    show_progress = not args.no_progress

    if args.mode == "export":
        src = Path(args.source).expanduser()
        dst = Path(args.target).expanduser()
        if not src.is_dir():
            print("Source folder does not exist or is not a directory.", file=sys.stderr)
            sys.exit(1)

        password = None
        if args.encrypt:
            if not HAVE_CRYPTO:
                print("Encryption requires 'cryptography'. Install with: pip install cryptography", file=sys.stderr)
                sys.exit(1)
            p1 = getpass("Enter password: ")
            p2 = getpass("Confirm password: ")
            if p1 != p2:
                print("Passwords do not match.", file=sys.stderr)
                sys.exit(1)
            password = p1

        if args.format == "json":
            export_json(src, dst, args.compress, args.encrypt, password, args.ignore, show_progress)
        else:
            export_txt(src, dst, args.compress, args.encrypt, password, args.ignore, show_progress)

        print(f"Folder exported to {dst}")

    else:  # import
        src = Path(args.source).expanduser()
        dst = Path(args.target).expanduser()
        if not src.is_file():
            print("Input file does not exist.", file=sys.stderr)
            sys.exit(1)
        dst.mkdir(parents=True, exist_ok=True)
        pwd = args.password  # may be None; will prompt if needed

        if src.suffix.lower() == ".json":
            import_json(src, dst, show_progress, pwd)
        else:
            import_txt(src, dst, show_progress, pwd)

        print(f"Folder imported to {dst}")


if __name__ == "__main__":
    main()
