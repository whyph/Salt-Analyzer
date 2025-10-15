#!/usr/bin/env python3
"""
Expected line format for these salted modes:  hash:salt

Features:
- Progress bars (tqdm if installed; otherwise periodic messages).
- Preflight estimator to avoid re-reading: samples early to estimate RAM and can start SQLite up-front.
- Interactive fallback threshold to switch to SQLite.
- Supports salts containing ':' (splits on the FIRST separator).
- Canonicalizes salts consistently across passes (important for $HEX[...] cases).
- If only --select-salts is used, default to per-salt files.
- NEW: Colored console output (Windows-friendly), toggled by --color.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import os
import re
import sqlite3
import sys
import tempfile
from collections import Counter
from typing import Dict, Iterator, List, Optional, Tuple

# Optional tqdm for progress bars
try:
    from tqdm import tqdm  # type: ignore
    _HAS_TQDM = True
except Exception:
    tqdm = None
    _HAS_TQDM = False

# Optional colorama for Windows ANSI support
_HAS_COLORAMA = False
try:
    import colorama  # type: ignore
    _HAS_COLORAMA = True
except Exception:
    pass

# ---------------- Colors ----------------

class _Ansi:
    RESET = "\x1b[0m"
    BOLD = "\x1b[1m"
    DIM = "\x1b[2m"
    # standard bright-ish palette
    RED = "\x1b[31m"
    GREEN = "\x1b[32m"
    YELLOW = "\x1b[33m"
    BLUE = "\x1b[34m"
    MAGENTA = "\x1b[35m"
    CYAN = "\x1b[36m"
    WHITE = "\x1b[37m"
    BRIGHT_RED = "\x1b[91m"
    BRIGHT_GREEN = "\x1b[92m"
    BRIGHT_YELLOW = "\x1b[93m"
    BRIGHT_BLUE = "\x1b[94m"
    BRIGHT_MAGENTA = "\x1b[95m"
    BRIGHT_CYAN = "\x1b[96m"
    BRIGHT_WHITE = "\x1b[97m"

_COLOR_ENABLED = False  # set in main after parsing

def _colorize(s: str, *codes: str) -> str:
    if not _COLOR_ENABLED:
        return s
    return "".join(codes) + s + _Ansi.RESET

def tag(level: str) -> str:
    """Colored bracket tags like [info], [warn], [preflight]."""
    m = {
        "info": (_Ansi.BRIGHT_CYAN, _Ansi.BOLD),
        "warn": (_Ansi.BRIGHT_YELLOW, _Ansi.BOLD),
        "preflight": (_Ansi.BRIGHT_MAGENTA, _Ansi.BOLD),
        "error": (_Ansi.BRIGHT_RED, _Ansi.BOLD),
    }
    codes = m.get(level, (_Ansi.BRIGHT_WHITE, _Ansi.BOLD))
    return _colorize(f"[{level}]", *codes)

def h1(s: str) -> str:
    return _colorize(s, _Ansi.BRIGHT_WHITE, _Ansi.BOLD)

def key(s: str) -> str:
    return _colorize(s, _Ansi.DIM)

def num(s: str) -> str:
    return _colorize(s, _Ansi.BRIGHT_CYAN)

def good(s: str) -> str:
    return _colorize(s, _Ansi.BRIGHT_GREEN)

def warn_txt(s: str) -> str:
    return _colorize(s, _Ansi.BRIGHT_YELLOW)

# -------------- Modes --------------

SUPPORTED_MODES = {
    # osCommerce
    21:   "osCommerce, xt:Commerce",
    
    # MD5 salted
    10:   "md5($pass.$salt)",
    20:   "md5($salt.$pass)",
    30:   "md5(utf16le($pass).$salt)",
    40:   "md5($salt.utf16le($pass))",

    # SHA-1 salted
    110:  "sha1($pass.$salt)",
    120:  "sha1($salt.$pass)",
    130:  "sha1(utf16le($pass).$salt)",
    140:  "sha1($salt.utf16le($pass))",

    # SHA-224 salted
    1310: "sha224($pass.$salt)",
    1320: "sha224($salt.$pass)",

    # SHA-256 salted
    1410: "sha256($pass.$salt)",
    1420: "sha256($salt.$pass)",
    1430: "sha256(utf16le($pass).$salt)",
    1440: "sha256($salt.utf16le($pass))",

    # SHA-384 salted
    10810: "sha384($pass.$salt)",
    10820: "sha384($salt.$pass)",
    10830: "sha384(utf16le($pass).$salt)",
    10840: "sha384($salt.utf16le($pass))",

    # SHA-512 salted
    1710: "sha512($pass.$salt)",
    1720: "sha512($salt.$pass)",
    1730: "sha512(utf16le($pass).$salt)",
    1740: "sha512($salt.utf16le($pass))",

    # vBulletin
    2611: "vBulletin < v3.8.5 (md5(md5($pass).$salt))",
    2711: "vBulletin >= v3.8.5 (md5(md5($pass).$salt))",
}

# -------------- I/O helpers --------------

def open_maybe_gzip(path: str, encoding: str, errors: str) -> Iterator[str]:
    if path.lower().endswith(".gz"):
        f = gzip.open(path, "rt", encoding=encoding, errors=errors)
    else:
        f = open(path, "rt", encoding=encoding, errors=errors)
    try:
        for line in f:
            yield line
    finally:
        f.close()

def ensure_dir(path: str) -> None:
    if path and not os.path.isdir(path):
        os.makedirs(path, exist_ok=True)

def is_gzip(path: str) -> bool:
    return path.lower().endswith(".gz")

# -------------- Progress wrappers --------------

def progress_wrap(iterable: Iterator[str],
                  desc: str,
                  enable_progress: bool,
                  progress_every: int = 100_000) -> Iterator[str]:
    if enable_progress and _HAS_TQDM:
        with tqdm(total=None, desc=desc, unit=" lines", mininterval=0.5) as bar:
            for item in iterable:
                yield item
                bar.update(1)
    else:
        for i, item in enumerate(iterable, 1):
            if enable_progress and progress_every and (i % progress_every == 0):
                print(f"{tag('info')} {_colorize(desc, _Ansi.BRIGHT_BLUE)} {key('processed=')}{num(f'{i:,}')}", file=sys.stderr)
            yield item

# -------------- Parsing --------------

HEX_SALT_RE = re.compile(r"^\$HEX\[(?P<h>[0-9A-Fa-f]*)\]$")

def extract_salt(line: str, sep: str) -> Optional[str]:
    """
    Extract salt by splitting on the FIRST occurrence of the separator.
    Supports salts that contain the separator (e.g., ':').
    """
    line = line.rstrip("\r\n")
    if not line:
        return None
    parts = line.split(sep, 1)
    if len(parts) != 2:
        return None
    salt = parts[1]
    return salt if salt != "" else None

def canonicalize_salt(s: str, hex_handling: str) -> str:
    """
    Normalize salt according to hex_handling:
      - 'keep'   : return s as-is
      - 'decode' : if $HEX[....], canonicalize lower-case hex inside wrapper
    """
    if hex_handling == "keep":
        return s
    m = HEX_SALT_RE.match(s)
    if m:
        return f"$HEX[{m.group('h').lower()}]"
    return s

# -------------- Memory info --------------

def _meminfo_psutil() -> Tuple[Optional[int], Optional[int]]:
    try:
        import psutil  # type: ignore
        vm = psutil.virtual_memory()
        return int(vm.total), int(vm.available)
    except Exception:
        return None, None

def _meminfo_windows() -> Tuple[Optional[int], Optional[int]]:
    try:
        import ctypes
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ('dwLength', ctypes.c_uint),
                ('dwMemoryLoad', ctypes.c_uint),
                ('ullTotalPhys', ctypes.c_ulonglong),
                ('ullAvailPhys', ctypes.c_ulonglong),
                ('ullTotalPageFile', ctypes.c_ulonglong),
                ('ullAvailPageFile', ctypes.c_ulonglong),
                ('ullTotalVirtual', ctypes.c_ulonglong),
                ('ullAvailVirtual', ctypes.c_ulonglong),
                ('sullAvailExtendedVirtual', ctypes.c_ulonglong),
            ]
        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
            return int(stat.ullTotalPhys), int(stat.ullAvailPhys)
    except Exception:
        pass
    return None, None

def _meminfo_linux() -> Tuple[Optional[int], Optional[int]]:
    try:
        total = avail = None
        with open("/proc/meminfo", "rt", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    total = int(line.split()[1]) * 1024
                elif line.startswith("MemAvailable:"):
                    avail = int(line.split()[1]) * 1024
        return total, avail
    except Exception:
        return None, None

def get_meminfo() -> Tuple[Optional[int], Optional[int]]:
    total, avail = _meminfo_psutil()
    if total is not None:
        return total, avail
    if sys.platform.startswith("win"):
        total, avail = _meminfo_windows()
        if total is not None:
            return total, avail
    if sys.platform.startswith("linux"):
        total, avail = _meminfo_linux()
        if total is not None:
            return total, avail
    return None, None

# -------------- Preflight estimator --------------

def preflight_estimate(
    path: str,
    sep: str,
    encoding: str,
    errors: str,
    hex_handling: str,
    sample_lines: int,
    gz_multiplier: float,
    uniq_growth: float,
    overhead_base: float,
    overhead_per_char: float,
    enable_progress: bool,
) -> Tuple[Optional[int], dict]:
    """
    Sample up to 'sample_lines' lines and estimate memory needed for an in-memory Counter.
    Returns (mem_bytes_est or None, debug_info dict).
    """
    is_gz = is_gzip(path)
    lines = 0
    valid = 0
    uniq = set()
    salt_len_sum = 0
    bytes_sum = 0

    it = progress_wrap(open_maybe_gzip(path, encoding, errors),
                       desc="Preflight", enable_progress=enable_progress, progress_every=0)
    for line in it:
        lines += 1
        bytes_sum += len(line.encode(encoding, errors="ignore"))
        s = extract_salt(line, sep)
        if s is not None:
            s = canonicalize_salt(s, hex_handling)
            uniq.add(s)
            salt_len_sum += len(s)
            valid += 1
        if lines >= sample_lines:
            break

    if lines == 0 or valid == 0:
        return None, {
            "lines_sampled": lines, "uniq_sample": 0, "avg_salt_len": 0.0,
            "avg_bytes_per_line": 0.0, "is_gz": is_gz, "lines_est": None, "uniq_est": 0,
        }

    avg_bytes_per_line = bytes_sum / lines
    avg_salt_len = (salt_len_sum / valid) if valid else 8.0
    uniq_sample = len(uniq)

    lines_est: Optional[int]
    if not is_gz:
        try:
            total_bytes = os.path.getsize(path)
            lines_est = max(1, int(total_bytes / max(1.0, avg_bytes_per_line)))
        except Exception:
            lines_est = None
    else:
        lines_est = None

    if lines_est is not None:
        uniq_est = int(min(lines_est,
                           max(uniq_sample, uniq_growth * (uniq_sample / lines) * lines_est)))
    else:
        uniq_est = int(max(uniq_sample, uniq_growth * uniq_sample * gz_multiplier))

    mem_per_unique = overhead_base + overhead_per_char * avg_salt_len
    mem_est = int(mem_per_unique * uniq_est)

    return mem_est, {
        "lines_sampled": lines,
        "uniq_sample": uniq_sample,
        "avg_salt_len": avg_salt_len,
        "avg_bytes_per_line": avg_bytes_per_line,
        "is_gz": is_gz,
        "lines_est": lines_est,
        "uniq_est": uniq_est,
        "mem_per_unique": mem_per_unique,
    }

# -------------- Counting (memory) --------------

def count_salts_memory(
    path: str,
    sep: str,
    encoding: str,
    errors: str,
    hex_handling: str,
    enable_progress: bool,
    progress_every: int,
) -> Tuple[Counter, int, int]:
    counts = Counter()
    total = 0
    bad = 0
    it = progress_wrap(open_maybe_gzip(path, encoding, errors),
                       desc="Pass1/mem", enable_progress=enable_progress,
                       progress_every=progress_every)
    for line in it:
        total += 1
        salt = extract_salt(line, sep)
        if salt is None:
            bad += 1
            continue
        salt = canonicalize_salt(salt, hex_handling)
        counts[salt] += 1
    return counts, total, bad

# -------------- Counting (sqlite) --------------

def count_salts_sqlite(
    path: str,
    sep: str,
    encoding: str,
    errors: str,
    hex_handling: str,
    db_path: Optional[str],
    enable_progress: bool,
    progress_every: int,
) -> Tuple[str, int, int]:
    if not db_path:
        tmpdir = tempfile.mkdtemp(prefix="salt_counts_")
        db_path = os.path.join(tmpdir, "counts.sqlite3")

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL;")
    cur.execute("PRAGMA synchronous=OFF;")
    cur.execute("CREATE TABLE IF NOT EXISTS counts (salt TEXT PRIMARY KEY, c INTEGER NOT NULL);")
    conn.commit()

    total = 0
    bad = 0
    batch: List[str] = []
    BATCH_SIZE = 5000

    def flush_batch():
        if not batch:
            return
        cur.execute("BEGIN;")
        for s in batch:
            cur.execute(
                "INSERT INTO counts (salt, c) VALUES (?, 1) "
                "ON CONFLICT(salt) DO UPDATE SET c = c + 1;",
                (s,),
            )
        conn.commit()
        batch.clear()

    it = progress_wrap(open_maybe_gzip(path, encoding, errors),
                       desc="Pass1/sqlite", enable_progress=enable_progress,
                       progress_every=progress_every)
    for line in it:
        total += 1
        salt = extract_salt(line, sep)
        if salt is None:
            bad += 1
            continue
        salt = canonicalize_salt(salt, hex_handling)
        batch.append(salt)
        if len(batch) >= BATCH_SIZE:
            flush_batch()

    flush_batch()
    conn.close()
    return db_path, total, bad

def fetch_counts_sqlite(db_path: str) -> List[Tuple[str, int]]:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT salt, c FROM counts ORDER BY c DESC, salt ASC;")
    rows = cur.fetchall()
    conn.close()
    return rows

# -------------- Emission (second pass) --------------

def sanitize_for_filename(s: str, limit: int = 80) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", s)
    if len(safe) > limit:
        safe = safe[:limit]
    digest = hashlib.md5(s.encode("utf-8", "replace")).hexdigest()[:8]
    return f"{safe}_{digest}"

def second_pass_emit(
    path: str,
    sep: str,
    encoding: str,
    errors: str,
    hex_handling: str,
    selected_salts: set,
    out_dir: str,
    per_salt: bool,
    combined_path: Optional[str],
    enable_progress: bool,
    progress_every: int,
) -> Tuple[int, int]:
    ensure_dir(out_dir)
    combined_file = open(combined_path, "wt", encoding="utf-8") if combined_path else None
    writers: Dict[str, any] = {}

    examined = 0
    emitted = 0

    it = progress_wrap(open_maybe_gzip(path, encoding, errors),
                       desc="Pass2/emit", enable_progress=enable_progress,
                       progress_every=progress_every)
    try:
        for line in it:
            examined += 1
            raw_salt = extract_salt(line, sep)
            if raw_salt is None:
                continue
            salt_key = canonicalize_salt(raw_salt, hex_handling)
            if salt_key not in selected_salts:
                continue

            if combined_file:
                combined_file.write(line)
            if per_salt:
                keyname = sanitize_for_filename(salt_key)
                if keyname not in writers:
                    writers[keyname] = open(os.path.join(out_dir, f"salt_{keyname}.txt"), "wt", encoding="utf-8")
                writers[keyname].write(line)
            emitted += 1
    finally:
        for f in writers.values():
            f.close()
        if combined_file:
            combined_file.close()
    return examined, emitted

# -------------- CSV summary --------------

def write_csv_summary(rows: List[Tuple[str,int]], csv_path: str, total_lines: int) -> None:
    ensure_dir(os.path.dirname(csv_path) or ".")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["salt", "count", "percent"])
        for salt, c in rows:
            pct = (c / total_lines * 100.0) if total_lines else 0.0
            w.writerow([salt, c, f"{pct:.4f}"])

# -------------- Helpers --------------

def ask_yes_no(prompt: str, default: bool = False) -> bool:
    yn = "Y/n" if default else "y/N"
    try:
        resp = input(f"{prompt} [{yn}]: ").strip().lower()
    except EOFError:
        return default
    if not resp:
        return default
    return resp in ("y", "yes")

# -------------- CLI --------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Analyze salt reuse in hashlists for salted hashcat modes.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-i", "--input", required=True, help="Path to hashlist (supports .gz). Each line like 'hash:salt'.")
    p.add_argument("-m", "--mode", type=int, required=True, choices=sorted(SUPPORTED_MODES.keys()),
                   help="Hashcat mode number.")
    p.add_argument("--sep", default=":", help="Field separator between hash and salt.")
    p.add_argument("--encoding", default="utf-8", help="Text encoding when reading the list.")
    p.add_argument("--errors", default="replace", choices=["strict", "ignore", "replace"],
                   help="Decoding error handling for problematic lines.")
    p.add_argument("--hex-salts", default="keep", choices=["keep", "decode"],
                   help="How to handle $HEX[...] salts for grouping.")

    # Colorized output
    p.add_argument("--color", choices=["auto", "always", "never"], default="auto",
                   help="Colored console output (auto enables on TTY).")

    # Counting backend + progress
    p.add_argument("--method", default="auto", choices=["auto", "mem", "sqlite"],
                   help="Counting backend. 'auto' may switch to SQLite based on preflight.")
    p.add_argument("--sqlite-db", default=None, help="Optional SQLite DB path (only for --method sqlite).")

    # Preflight options
    p.add_argument("--preflight", action="store_true", default=True,
                   help="(default) Sample early to estimate RAM need before counting.")
    p.add_argument("--no-preflight", dest="preflight", action="store_false",
                   help="Skip preflight and behave like earlier versions.")
    p.add_argument("--preflight-lines", type=int, default=200000,
                   help="How many lines to sample for estimation.")
    p.add_argument("--mem-budget-frac", type=float, default=0.6,
                   help="Max fraction of available RAM for Counter before switching to SQLite.")
    p.add_argument("--preflight-uniq-growth", type=float, default=1.0,
                   help="Growth factor when extrapolating unique salts from sample.")
    p.add_argument("--preflight-gz-multiplier", type=float, default=10.0,
                   help="For .gz (unknown total lines), multiply sample uniques by this.")
    p.add_argument("--mem-overhead-base", type=float, default=200.0,
                   help="Base bytes per unique salt (dict entry + objects).")
    p.add_argument("--mem-overhead-per-char", type=float, default=2.0,
                   help="Extra bytes per character of salt for the estimate.")

    # Threshold + prompt fallback
    p.add_argument("--sqlite-threshold", type=int, default=2_000_000,
                   help="If unique salts exceed this after Pass 1 (mem), offer to re-run with SQLite.")
    p.add_argument("--prompt-sqlite", action="store_true", default=True,
                   help="(default) Prompt to re-run with SQLite when threshold triggers.")
    p.add_argument("--no-prompt-sqlite", dest="prompt_sqlite", action="store_false",
                   help="Do not prompt; keep in-memory result even if threshold triggers.")
    p.add_argument("-y", "--assume-yes", action="store_true",
                   help="Auto-confirm switching to SQLite when prompted (non-interactive).")

    p.add_argument("--progress", dest="progress", action="store_true", default=True,
                   help="Show progress bars/messages (default).")
    p.add_argument("--no-progress", dest="progress", action="store_false",
                   help="Disable progress bars/messages.")
    p.add_argument("--progress-every", type=int, default=100000,
                   help="Fallback print frequency when tqdm is unavailable or disabled.")

    # Summary + outputs
    p.add_argument("--top", type=int, default=20, help="Show top N salts in console summary.")
    p.add_argument("--csv", default=None, help="Write full salt frequency CSV here.")
    p.add_argument("-o", "--output-dir", default="salt_outputs", help="Directory for any emitted hash lines.")
    p.add_argument("--emit-combined", type=int, default=0,
                   help="Emit one file with all lines for the top N salts.")
    p.add_argument("--emit-per-salt", type=int, default=0,
                   help="Emit one file per salt for the top N salts.")
    p.add_argument("--select-salts", nargs="*", default=None,
                   help="Explicit salts to emit (in addition to any --emit-* selections).")
    p.add_argument("--combined-name", default=None,
                   help="Filename for the combined output (defaults to combined_topN.txt).")

    return p.parse_args(argv)

# -------------- Main --------------

def main(argv: Optional[List[str]] = None) -> int:
    global _COLOR_ENABLED

    args = parse_args(argv)

    # Enable colors?
    _COLOR_ENABLED = (args.color == "always") or (args.color == "auto" and sys.stderr.isatty())
    if _COLOR_ENABLED and _HAS_COLORAMA:
        # ensure ANSI works on Windows consoles too
        colorama.just_fix_windows_console()

    print(f"{tag('info')} Mode {num(str(args.mode))} = {_colorize(SUPPORTED_MODES[args.mode], _Ansi.BRIGHT_BLUE)}", file=sys.stderr)
    print(f"{tag('info')} Reading {_colorize(args.input, _Ansi.BRIGHT_BLUE)}", file=sys.stderr)

    # ---------- Preflight ----------
    chosen_method = args.method
    if args.method in ("auto", "mem") and args.preflight:
        total_mem, avail_mem = get_meminfo()
        if avail_mem is not None:
            mem_est, dbg = preflight_estimate(
                path=args.input,
                sep=args.sep,
                encoding=args.encoding,
                errors=args.errors,
                hex_handling=args.hex_salts,
                sample_lines=args.preflight_lines,
                gz_multiplier=args.preflight_gz_multiplier,
                uniq_growth=args.preflight_uniq_growth,
                overhead_base=args.mem_overhead_base,
                overhead_per_char=args.mem_overhead_per_char,
                enable_progress=args.progress,
            )
            if mem_est is not None:
                budget = int(args.mem_budget_frac * avail_mem)
                print(f"{tag('preflight')} {key('lines_sampled=')}{num(f'{dbg['lines_sampled']:,}')}  "
                      f"{key('uniq_sample=')}{num(f'{dbg['uniq_sample']:,}')}  "
                      f"{key('avg_salt_len=')}{num(f'{dbg['avg_salt_len']:.2f}')}  "
                      f"{key('is_gz=')}{num(str(dbg['is_gz']))}  "
                      f"{key('lines_est=')}{num(str(dbg['lines_est']))}  "
                      f"{key('uniq_est=')}{num(f'{dbg['uniq_est']:,}')}  "
                      f"{key('mem_need_est≈')}{warn_txt(f'{mem_est:,}')}  "
                      f"{key('avail≈')}{num(f'{avail_mem:,}')}  {key('budget≈')}{num(f'{budget:,}')}",
                      file=sys.stderr)
                if mem_est > budget and args.method == "auto":
                    chosen_method = "sqlite"
                    print(f"{tag('preflight')} {warn_txt('Estimated memory too high; starting in SQLite to avoid a second full read.')}",
                          file=sys.stderr)
        else:
            print(f"{tag('preflight')} {warn_txt('Could not determine available memory; proceeding with current method.')}",
                  file=sys.stderr)

    # ---------- Pass 1 ----------
    rows: List[Tuple[str, int]]
    if chosen_method in ("auto", "mem"):
        counts, total, bad = count_salts_memory(
            path=args.input,
            sep=args.sep,
            encoding=args.encoding,
            errors=args.errors,
            hex_handling=args.hex_salts,
            enable_progress=args.progress,
            progress_every=args.progress_every,
        )
        rows = counts.most_common()

        # Fallback interactive threshold
        uniq = len(rows)
        if args.method == "auto" and chosen_method != "sqlite" and uniq > args.sqlite_threshold:
            print(f"{tag('warn')} Very high number of unique salts detected {num(f'({uniq:,})')}. "
                  f"SQLite mode can limit RAM usage.", file=sys.stderr)
            do_switch = False
            if args.prompt_sqlite:
                if args.assume_yes:
                    do_switch = True
                else:
                    do_switch = ask_yes_no("Re-run counting with SQLite now?", default=False)
            if do_switch:
                print(f"{tag('info')} Re-running Pass 1 with SQLite...", file=sys.stderr)
                db_path, total, bad = count_salts_sqlite(
                    path=args.input,
                    sep=args.sep,
                    encoding=args.encoding,
                    errors=args.errors,
                    hex_handling=args.hex_salts,
                    db_path=args.sqlite_db,
                    enable_progress=args.progress,
                    progress_every=args.progress_every,
                )
                print(f"{tag('info')} Counts stored in SQLite: {_colorize(db_path, _Ansi.BRIGHT_BLUE)}", file=sys.stderr)
                rows = fetch_counts_sqlite(db_path)
    else:
        db_path, total, bad = count_salts_sqlite(
            path=args.input,
            sep=args.sep,
            encoding=args.encoding,
            errors=args.errors,
            hex_handling=args.hex_salts,
            db_path=args.sqlite_db,
            enable_progress=args.progress,
            progress_every=args.progress_every,
        )
        print(f"{tag('info')} Counts stored in SQLite: {_colorize(db_path, _Ansi.BRIGHT_BLUE)}", file=sys.stderr)
        rows = fetch_counts_sqlite(db_path)

    valid = (total - bad)
    uniq = len(rows)

    # ---------- Summary ----------
    print("")
    print(h1("=== Salt Summary ==="))
    print(f"{key('Total lines         :')} {num(f'{total:,}')}")
    print(f"{key('Valid lines         :')} {good(f'{valid:,}')}")
    print(f"{key('Invalid/unsplit     :')} {warn_txt(f'{bad:,}')}")
    print(f"{key('Unique salts        :')} {num(f'{uniq:,}')}")
    print("")
    topn = min(args.top, uniq)
    print(h1(f"Top {topn} salts:"))
    for salt, c in rows[: topn]:
        pct = (c / valid * 100.0) if valid else 0.0
        show = salt if salt != "" else "[EMPTY]"
        print(f"  {_colorize(f'{show:40s}', _Ansi.BRIGHT_WHITE)}  {num(f'{c:10,d}')}  {key(f'{pct:6.2f}%')}")

    # ---------- CSV ----------
    if args.csv:
        write_csv_summary(rows, args.csv, valid)
        print(f"{tag('info')} Wrote CSV summary: {_colorize(args.csv, _Ansi.BRIGHT_BLUE)}", file=sys.stderr)

    # ---------- Build selection for Pass 2 ----------
    selections: set = set()
    if args.emit_combined > 0:
        for s, _ in rows[: args.emit_combined]:
            selections.add(s)
    if args.emit_per_salt > 0:
        for s, _ in rows[: args.emit_per_salt]:
            selections.add(s)
    if args.select_salts:
        for s in args.select_salts:
            selections.add(canonicalize_salt(s, args.hex_salts))

    auto_per_salt_for_selected = bool(args.select_salts) and args.emit_per_salt == 0 and args.emit_combined == 0

    if selections:
        combined_path = None
        per_salt = (args.emit_per_salt > 0) or auto_per_salt_for_selected

        if args.emit_combined > 0:
            name = args.combined_name or f"combined_top{args.emit_combined}.txt"
            combined_path = os.path.join(args.output_dir, name)

        examined, emitted = second_pass_emit(
            path=args.input,
            sep=args.sep,
            encoding=args.encoding,
            errors=args.errors,
            hex_handling=args.hex_salts,
            selected_salts=selections,
            out_dir=args.output_dir,
            per_salt=per_salt,
            combined_path=combined_path,
            enable_progress=args.progress,
            progress_every=args.progress_every,
        )
        print("")
        print(h1("=== Emission ==="))
        print(f"{key('Second pass examined:')} {num(f'{examined:,}')}")
        print(f"{key('Lines emitted       :')} {good(f'{emitted:,}')}")
        if combined_path:
            print(f"{key('Combined file       :')} {_colorize(combined_path, _Ansi.BRIGHT_BLUE)}")
        if per_salt:
            print(f"{key('Per-salt files dir  :')} {_colorize(args.output_dir, _Ansi.BRIGHT_BLUE)}")

    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print(f"\n{tag('error')} Interrupted.", file=sys.stderr)
        raise

