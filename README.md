# Salt-Analyzer
A fast, memory-savvy CLI that scans large hashlists and analyzes salt reuse. It’s built for hashcat’s salted “generic” modes (MD5/SHA-1/SHA-224/SHA-256/SHA-384/SHA-512) plus vBulletin formats, shows clear summaries (with progress bars and colored output), and can optionally export the original hash lines for the most common salts.

## Why?
Salt reuse weakens cracking resistance. When you inherit giant hashlists, it’s useful to know:
* How many salts are unique vs. reused
* Which salts dominate (e.g., `1234`, `SaLtEd`, `Salt:`…)
* Quickly carve out subsets of the list grouped by salt for targeted workflows

This tool streams the file once (or twice when exporting), keeps RAM use predictable, and plays nicely with huge inputs.
***
### Features
* **Hashcat-mode aware:** script hash type mirrors hash type code of hashcat.
* **Salts with colons:** splits on the first separator so salts can contain `:`.
* **$HEX[…] salts:** optional canonicalization (`--hex-salts decode`) collapses case variants.
* **Colored output** with `--color {auto,always,never}` (Windows supported via colorama).
* **Preflight memory estimator:** samples early to predict RAM, optionally starts SQLite mode up-front to avoid a second full read.
* **SQLite backend** for near-constant RAM on massive unique-salt sets.
* **CSV report** of all salts with counts & percentages.
* **Second-pass emit:**
    * **Combined** file for top-N salts
    * **Per-salt** files for top-N salts
    * **Specific salts** via `--select-salts` (auto-creates per-salt files)

### Supported modes
**MD5:** `10` md5($pass.$salt) · `20` md5($salt.$pass) · `30` md5(utf16le($pass).$salt) · `40` md5($salt.utf16le($pass))

**SHA-1:** `110` sha1($pass.$salt) · `120` sha1($salt.$pass) · `130` sha1(utf16le($pass).$salt) · `140` sha1($salt.utf16le($pass))

**SHA-224:** `1310` sha224($pass.$salt) · `1320` sha224($salt.$pass)

**SHA-256:** `1410` sha256($pass.$salt) · `1420` sha256($salt.$pass) · `1430` sha256(utf16le($pass).$salt) · `1440` sha256($salt.utf16le($pass))

**SHA-384:** `10810` sha384($pass.$salt) · `10820` sha384($salt.$pass) · `10830` sha384(utf16le($pass).$salt) · `10840` sha384($salt.utf16le($pass))

**SHA-512:** `1710` sha512($pass.$salt) · `1720` sha512($salt.$pass) · `1730` sha512(utf16le($pass).$salt) · `1740` sha512($salt.utf16le($pass))

**vBulletin:** `2611` vBulletin < 3.8.5 (md5(md5($pass).$salt)) · `2711` vBulletin ≥ 3.8.5 (md5(md5($pass).$salt))

> This tool **analyzes** salts; it doesn’t verify digest correctness or crack hashes.
***
## Install
Requires **Python 3.8+**. The script has no hard dependencies.
<br>
Optional (for a nicer UX):
```python
pip install tqdm colorama psutil
```
* `tqdm` → progress bars
* `colorama` → ANSI colors on Windows terminals
* `psutil` → better memory detection for preflight

### Quick start
```bash
# Show a top-20 salt summary for sha256($pass.$salt)
python salt_analyzer.py -i hashes.txt -m 1410

# Write a full CSV and export all lines that use the top 10 salts (combined)
python salt_analyzer.py -i hashes.txt -m 110 --csv salts_summary.csv \
  --emit-combined 10 -o out

# Create one file per salt for the top 5 salts
python salt_analyzer.py -i hashes.txt.gz -m 1720 --emit-per-salt 5 -o out

# Export specific salts (auto-creates per-salt files), even if they contain ':'
python salt_analyzer.py -i hashes.txt -m 120 --select-salts Salt: SaLtEd -o out
```
***
### Typical output
```yaml
=== Salt Summary ===
Total lines         : 12,540,993
Valid lines         : 12,540,993
Invalid/unsplit     : 0
Unique salts        : 4,381

Top 10 salts:
  1234                                     89,112     0.71%
  SaLtEd                                   70,020     0.56%
  attack:                                  58,991     0.47%
  $HEX[313233]                             55,400     0.44%
  ...
```
***
### Usage (common flags)
```pgsql
-i, --input PATH           Path to hashlist (supports .gz). Format: hash:salt
-m, --mode INT             Hashcat mode number (see list above)

--sep ":"                  Field separator (default ":")
--hex-salts {keep,decode}  Canonicalize $HEX[....] salts (default keep)

--method {auto,mem,sqlite} Counting backend (default auto)
--preflight / --no-preflight
                           Sample early to estimate RAM (default on)
--preflight-lines N        Sample size for estimator (default 200k)
--mem-budget-frac FLOAT    Switch to SQLite if estimate > fraction of free RAM (default 0.6)

--sqlite-db FILE           Use/keep a specific SQLite DB file
--sqlite-threshold N       If unique salts > N after mem pass, offer SQLite (default 2,000,000)
-y, --assume-yes           Auto-accept SQLite prompt

--progress / --no-progress Show progress bars or periodic counters
--color {auto,always,never} Colored console output (default auto)

--top N                    Show top-N salts (default 20)
--csv FILE                 Write full CSV summary (salt,count,percent)
-o, --output-dir DIR       Output directory (default ./salt_outputs)
--emit-combined N          One file with lines for the top N salts
--emit-per-salt N          One file per salt for the top N salts
--select-salts S [S...]    Explicit salts to emit (in addition to any --emit-* selections)
--combined-name NAME       Set combined output filename
```
***
## Large files & memory
* **Preflight estimator:** by default, the tool samples the first `--preflight-lines` lines, estimates unique salt growth and per-entry overhead, and starts in SQLite immediately if the estimate would exceed `--mem-budget-frac` of available RAM.
* **SQLite mode:** disk-backed counting with upserts keeps memory stable for millions of unique salts.
* **Gzip input:** supported; for `.gz` the estimator uses a conservative multiplier (`--preflight-gz-multiplier`, default 10) since total decompressed lines are unknown.
#### Tuning tips
* Bump `--preflight-lines` for more accurate projections.
* Lower `--mem-budget-frac` on memory-constrained machines.
* Set `--method sqlite` to force disk-backed counting from the start.
***
### Output files
* **CSV:** `salt,count,percent` (for all salts, sorted by count desc).
* **Combined:** `combined_topN.txt` (or `--combined-name`) — all original lines whose salt is in the top-N set.
* **Per-salt:** `salt_<sanitized>_<digest>.txt` — one file per salt (top-N or `--select-salts`). Filenames are sanitized and include an 8-char MD5 of the original salt to avoid collisions.
***
### Notes & assumptions
* **Delimiter:** default `:`; the script splits on the first occurrence so salts can contain `:`. Change via `--sep`.
* **$HEX[…] salts:** use `--hex-salts decode` to normalize the hex wrapper to lowercase and avoid duplicates caused by case differences.
* **Mode semantics:** modes are used only as labels for your workflow; the analyzer does not recompute or validate hashes.
* **Encoding:** reads with `--encoding utf-8` by default; use `--errors` (`replace|ignore|strict`) for noisy inputs.
* **Performance:** in-memory `Counter` is fastest; SQLite trades speed for stability on extreme cardinalities.
***
### Roadmap ideas
* Optional pretty tables (e.g., `rich`) for summaries.
* JSON output alongside CSV.
* Pluggable parsers for non-`hash:salt` formats.
***
### Acknowledgements
This project’s script and README were created with the assistance of **ChatGPT** (OpenAI) and refined through real-world testing.
