#!/usr/bin/env python3
"""Merge public DNS blocklists into a FRITZ!Box wildcard-domains list.

Output format (one domain per line) matches the AVM "wildcard domains"
format documented in FRITZ! knowledge base #4463. Stdlib only.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover
    ZoneInfo = None  # type: ignore


REPO_ROOT = Path(__file__).resolve().parent.parent

SOURCES = (
    {
        "id": "oisd",
        "name": "OISD Big",
        "url": "https://big.oisd.nl",
        "kind": "adblock",
    },
    {
        "id": "hagezi",
        "name": "HaGeZi Pro",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt",
        "kind": "adblock",
    },
    {
        "id": "stevenblack",
        "name": "Steven Black Hosts",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "kind": "hosts",
    },
)

USER_AGENT = (
    "dns-blocklist-builder/1.0 "
    "(+https://github.com/HorstHauser/dns-blocklist)"
)
TIMEOUT_SECONDS = 90
RETRIES = 3
RETRY_BACKOFF = 2.0
MIN_VALID_DOMAINS = 1000
SHRINK_RATIO = 0.5

RESERVED_NAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "broadcasthost",
        "local",
        "0.0.0.0",
        "ip6-localhost",
        "ip6-loopback",
        "ip6-localnet",
        "ip6-mcastprefix",
        "ip6-allnodes",
        "ip6-allrouters",
        "ip6-allhosts",
    }
)

# Label: LDH / punycode (xn--...). Underscores are not valid host labels.
LABEL_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)$")
HOSTS_IP_RE = re.compile(r"^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]+)\s+", re.I)
ABP_HEADER_RE = re.compile(r"^\[Adblock", re.I)


class BuildError(Exception):
    """Fatal build error; process should exit with code 1."""


def now_berlin() -> datetime:
    if ZoneInfo is not None:
        return datetime.now(ZoneInfo("Europe/Berlin"))
    return datetime.now().astimezone()


def fetch_text(url: str) -> tuple[str, int]:
    """Download URL with timeout and retries. Returns (text, http_status)."""
    last_error: Exception | None = None
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/plain, text/*, */*",
        "Accept-Encoding": "identity",
    }
    for attempt in range(1, RETRIES + 1):
        try:
            request = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
                status = getattr(response, "status", 200) or 200
                if status != 200:
                    raise BuildError(f"{url}: HTTP {status}")
                data = response.read()
            if not data:
                raise BuildError(f"{url}: leere Antwort")
            # Reject obvious HTML error pages early.
            head = data[:256].lstrip().lower()
            if head.startswith(b"<!doctype html") or head.startswith(b"<html"):
                raise BuildError(f"{url}: HTML statt Texliste erhalten")
            return data.decode("utf-8", errors="replace"), status
        except BuildError as exc:
            last_error = exc
            # Do not retry permanent client errors hidden as BuildError for HTML
            # or empty body — but do retry after a short wait in case of a glitch.
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code in {400, 401, 403, 404, 410}:
                raise BuildError(f"{url}: HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = exc
        if attempt < RETRIES:
            time.sleep(RETRY_BACKOFF**attempt)
    raise BuildError(f"{url}: Download fehlgeschlagen nach {RETRIES} Versuchen ({last_error})")


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize_domain(raw: str) -> str | None:
    """Lowercase, strip trailing dots / leading wildcards, validate syntax."""
    if not raw:
        return None
    text = raw.strip().strip("[]").lower()
    if not text or text.startswith("#") or text.startswith("!"):
        return None
    text = text.rstrip(".")
    while text.startswith("*."):
        text = text[2:]
        text = text.lstrip(".")
    if not text or "/" in text or ":" in text or " " in text or "?" in text:
        return None
    if "%" in text or "\\" in text or text.startswith("."):
        return None
    if is_ip_address(text) or text in RESERVED_NAMES or text.startswith("ip6-"):
        return None
    # IDNA: Unicode domains → punycode; already-ASCII names stay as-is.
    try:
        ascii_name = text.encode("idna").decode("ascii")
    except (UnicodeError, LookupError):
        return None
    if len(ascii_name) > 253:
        return None
    labels = ascii_name.split(".")
    # At least domain + TLD. A lone label (e.g. "com") would be catastrophic.
    if len(labels) < 2:
        return None
    if labels[-1].isdigit() or not labels[-1].isalpha() and not labels[-1].startswith("xn--"):
        # TLD must be letters or punycode, not digits / mixed junk.
        if not re.fullmatch(r"[a-z]{2,63}", labels[-1]) and not labels[-1].startswith("xn--"):
            return None
    for label in labels:
        if not label or len(label) > 63 or not LABEL_RE.fullmatch(label):
            return None
    return ascii_name


def _looks_like_regex(line: str) -> bool:
    if len(line) >= 2 and line.startswith("/") and "/" in line[1:]:
        # Adblock regex rules: /pattern/ or /pattern/flags
        return True
    return False


def _looks_like_cosmetic(line: str) -> bool:
    for marker in ("##", "#@#", "#?#", "#$?#", "$$"):
        if marker in line:
            return True
    return False


def parse_adblock_line(line: str) -> str | None:
    text = line.strip()
    if not text or text.startswith("!") or text.startswith("#") or ABP_HEADER_RE.match(text):
        return None
    if text.startswith("@@"):
        return None  # exceptions
    if _looks_like_cosmetic(text) or _looks_like_regex(text):
        return None
    if text.startswith("||"):
        body = text[2:]
        # Path rules (anything with "/" before the end-anchor) are discarded.
        cut = len(body)
        for sep in ("^", "$", "|", ",", " "):
            pos = body.find(sep)
            if pos != -1:
                cut = min(cut, pos)
        candidate = body[:cut]
        if "/" in candidate:
            return None
        # Allow a single leading "*." (wildcard prefix); other globs are not domains.
        if candidate.startswith("*."):
            rest = candidate[2:]
            if not rest or "*" in rest:
                return None
        elif "*" in candidate:
            return None
        return normalize_domain(candidate)
    # Plain domain line (already-normalized wildcard lists, mixed files).
    if text.startswith("|") or text.startswith("/") or text.startswith("*"):
        return None
    if HOSTS_IP_RE.match(text):
        return parse_hosts_line(text)
    if " " in text or "$" in text or "=" in text:
        return None
    return normalize_domain(text)


def parse_hosts_line(line: str) -> str | None:
    text = line.strip()
    if not text or text.startswith("#"):
        return None
    if "#" in text:
        text = text[: text.index("#")].strip()
    parts = text.split()
    if not parts:
        return None
    # Classic hosts: IP followed by one or more names. Return first valid name.
    # (Caller that needs all names uses parse_hosts_line_all.)
    names = parts[1:] if is_ip_address(parts[0]) else parts
    for name in names:
        domain = normalize_domain(name)
        if domain:
            return domain
    return None


def parse_hosts_line_all(line: str) -> list[str]:
    text = line.strip()
    if not text or text.startswith("#"):
        return []
    if "#" in text:
        text = text[: text.index("#")].strip()
    parts = text.split()
    if not parts:
        return []
    names = parts[1:] if is_ip_address(parts[0]) else parts
    out: list[str] = []
    for name in names:
        domain = normalize_domain(name)
        if domain:
            out.append(domain)
    return out


def parse_lines(text: str, kind: str) -> tuple[list[str], int]:
    """Return (valid domains in file order, raw line count)."""
    raw_lines = text.splitlines()
    domains: list[str] = []
    if kind == "hosts":
        for line in raw_lines:
            domains.extend(parse_hosts_line_all(line))
    else:
        # adblock, with hosts-line fallback already inside parse_adblock_line
        for line in raw_lines:
            domain = parse_adblock_line(line)
            if domain:
                domains.append(domain)
    return domains, len(raw_lines)


def load_allowlist(path: Path) -> set[str]:
    if not path.exists():
        return set()
    allowed: set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        if "#" in text:
            text = text[: text.index("#")].strip()
        domain = normalize_domain(text)
        if domain:
            allowed.add(domain)
    return allowed


def is_allowed(domain: str, allowlist: set[str]) -> bool:
    if domain in allowlist:
        return True
    parts = domain.split(".")
    for i in range(1, len(parts) - 1):
        parent = ".".join(parts[i:])
        if parent in allowlist:
            return True
    # also exact parent that is a 2-label domain, covered by the loop when
    # len(parts) > 2; for two-label domains only exact match applies.
    return False


def collapse_subdomains(domains: Iterable[str]) -> tuple[list[str], int]:
    """Drop entries whose parent domain is already present.

    Only meaningful if the consumer treats a listed domain as a wildcard
    covering all subdomains (see HaGeZi FAQ / AVM 'wildcard domains').
    """
    # Parents first: fewer labels come first.
    ordered = sorted(set(domains), key=lambda d: (d.count("."), d))
    kept: list[str] = []
    kept_set: set[str] = set()
    removed = 0
    for domain in ordered:
        parts = domain.split(".")
        covered = False
        for i in range(1, len(parts) - 1 + 1):
            # Check every suffix that is still a FQDN (at least two labels).
            if len(parts) - i < 2:
                break
            parent = ".".join(parts[i:])
            if parent in kept_set:
                covered = True
                break
        if covered:
            removed += 1
            continue
        kept.append(domain)
        kept_set.add(domain)
    return kept, removed


def previous_counts(stats_path: Path) -> dict[str, int]:
    if not stats_path.exists():
        return {}
    try:
        payload = json.loads(stats_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    sources = payload.get("sources") or {}
    counts: dict[str, int] = {}
    for source_id, info in sources.items():
        if isinstance(info, dict) and isinstance(info.get("valid_domains"), int):
            counts[source_id] = info["valid_domains"]
    return counts


def write_blocklist(
    path: Path,
    domains: list[str],
    created: datetime,
    source_stats: list[dict],
    duplicates: int,
    allowlist_removed: int,
    collapsed: int,
    collapse_enabled: bool,
) -> None:
    created_label = created.strftime("%Y-%m-%d %H:%M:%S %Z")
    lines = [
        "# FRITZ!Box DNS-Sperrliste (Wildcard-Domains-Format, eine Domain pro Zeile)",
        f"# Erstellt: {created_label}",
        "# Quellen (gültige Domains / Rohzeilen):",
    ]
    for info in source_stats:
        lines.append(
            f"#   {info['id']}: {info['valid_domains']} / {info['raw_lines']}"
            f"  ({info['url']})"
        )
    extra = f"# Zusammengeführt: {len(domains)} eindeutig, {duplicates} Duplikate entfernt"
    if allowlist_removed:
        extra += f", {allowlist_removed} per Allowlist entfernt"
    if collapse_enabled:
        extra += f", {collapsed} Subdomains unter bereits gesperrten Eltern entfernt"
    lines.append(extra)
    lines.append(
        "# Lizenzen der Quellen: OISD GPL-3.0, HaGeZi GPL-3.0, Steven Black MIT."
    )
    lines.append("# Die zusammengeführte Liste steht unter GPL-3.0.")
    lines.append("")
    lines.extend(domains)
    lines.append("")
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text("\n".join(lines), encoding="utf-8")
    tmp.replace(path)


def build(args: argparse.Namespace) -> int:
    started = time.perf_counter()
    created = now_berlin()
    output_path = Path(args.output)
    stats_path = Path(args.stats)
    if not output_path.is_absolute():
        output_path = REPO_ROOT / output_path
    if not stats_path.is_absolute():
        stats_path = REPO_ROOT / stats_path
    allowlist_path = Path(args.allowlist)
    if not allowlist_path.is_absolute():
        allowlist_path = REPO_ROOT / allowlist_path

    prev = previous_counts(stats_path)
    source_sets: dict[str, set[str]] = {}
    source_stats: list[dict] = []

    for source in SOURCES:
        print(f"Lade {source['name']} ({source['url']}) …", flush=True)
        text, status = fetch_text(source["url"])
        raw_bytes = len(text.encode("utf-8"))
        domains, raw_lines = parse_lines(text, source["kind"])
        unique = set(domains)
        print(
            f"  Rohzeilen: {raw_lines}, gültige Domains: {len(unique)} "
            f"(inkl. interner Duplikate: {len(domains) - len(unique)}), "
            f"{raw_bytes} Bytes, HTTP {status}",
            flush=True,
        )
        if len(unique) < MIN_VALID_DOMAINS:
            raise BuildError(
                f"{source['id']}: nur {len(unique)} gültige Domains "
                f"(Minimum {MIN_VALID_DOMAINS}) — Quelle fehlt oder ist verdächtig klein"
            )
        previous = prev.get(source["id"])
        if previous is not None and len(unique) < previous * SHRINK_RATIO:
            raise BuildError(
                f"{source['id']}: {len(unique)} gültige Domains, "
                f"letzter Lauf {previous} — unter {int(SHRINK_RATIO * 100)} %, Abbruch"
            )
        source_sets[source["id"]] = unique
        source_stats.append(
            {
                "id": source["id"],
                "name": source["name"],
                "url": source["url"],
                "kind": source["kind"],
                "http_status": status,
                "raw_bytes": raw_bytes,
                "raw_lines": raw_lines,
                "valid_domains": len(unique),
                "internal_duplicates": len(domains) - len(unique),
            }
        )

    # Union / duplicates / overlap
    ids = [s["id"] for s in SOURCES]
    all_listed = []
    for sid in ids:
        all_listed.extend(source_sets[sid])
    counts = Counter(all_listed)
    union = set(counts)
    duplicates = sum(n - 1 for n in counts.values() if n > 1)
    unique_in_several = sum(1 for n in counts.values() if n > 1)

    overlap = {
        "oisd_and_hagezi": len(source_sets["oisd"] & source_sets["hagezi"]),
        "oisd_and_stevenblack": len(source_sets["oisd"] & source_sets["stevenblack"]),
        "hagezi_and_stevenblack": len(source_sets["hagezi"] & source_sets["stevenblack"]),
        "all_three": len(
            source_sets["oisd"] & source_sets["hagezi"] & source_sets["stevenblack"]
        ),
        "only_oisd": len(
            source_sets["oisd"] - source_sets["hagezi"] - source_sets["stevenblack"]
        ),
        "only_hagezi": len(
            source_sets["hagezi"] - source_sets["oisd"] - source_sets["stevenblack"]
        ),
        "only_stevenblack": len(
            source_sets["stevenblack"] - source_sets["oisd"] - source_sets["hagezi"]
        ),
        "domains_in_several_sources": unique_in_several,
    }

    allowlist = load_allowlist(allowlist_path)
    allowed_removed = {d for d in union if is_allowed(d, allowlist)}
    remaining = union - allowed_removed

    collapsed = 0
    if args.collapse_subdomains:
        ordered, collapsed = collapse_subdomains(remaining)
    else:
        ordered = sorted(remaining)

    write_blocklist(
        output_path,
        ordered,
        created,
        source_stats,
        duplicates=duplicates,
        allowlist_removed=len(allowed_removed),
        collapsed=collapsed,
        collapse_enabled=args.collapse_subdomains,
    )
    runtime = round(time.perf_counter() - started, 3)
    payload = {
        "timestamp": created.isoformat(timespec="seconds"),
        "timestamp_utc": created.astimezone(timezone.utc).isoformat(timespec="seconds"),
        "runtime_seconds": runtime,
        "collapse_subdomains": args.collapse_subdomains,
        "sources": {item["id"]: item for item in source_stats},
        "union_mentions": len(all_listed),
        "unique_after_dedupe": len(union),
        "duplicates": duplicates,
        "overlap": overlap,
        "allowlist_file": str(allowlist_path.name),
        "allowlist_entries": len(allowlist),
        "allowlist_removed": len(allowed_removed),
        "collapsed_subdomains": collapsed,
        "total": len(ordered),
        "output_file": output_path.name,
        "output_bytes": output_path.stat().st_size,
    }
    stats_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(
        f"Fertig: {len(ordered)} Domains in {output_path} "
        f"({payload['output_bytes']} Bytes), Laufzeit {runtime}s",
        flush=True,
    )
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-o",
        "--output",
        default="blocklist.txt",
        help="Ausgabedatei (Standard: blocklist.txt im Repo-Root)",
    )
    parser.add_argument(
        "--stats",
        default="stats.json",
        help="Statistikdatei (Standard: stats.json im Repo-Root)",
    )
    parser.add_argument(
        "--allowlist",
        default="allowlist.txt",
        help="Ausnahmeliste (Standard: allowlist.txt im Repo-Root)",
    )
    parser.add_argument(
        "--no-collapse-subdomains",
        dest="collapse_subdomains",
        action="store_false",
        help=(
            "Keine Subdomains entfernen, deren Elterndomain bereits gesperrt ist. "
            "Standard: Subdomains werden zusammengefasst (FRITZ!Box sperrt Mitschnitte)."
        ),
    )
    parser.set_defaults(collapse_subdomains=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        return build(args)
    except BuildError as exc:
        print(f"Fehler: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
