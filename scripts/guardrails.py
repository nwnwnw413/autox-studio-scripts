#!/usr/bin/env python3
"""Deterministic pre-review checks for one Auto-X item (NyxBot edition, contract v0.2.1).

Ported from Auto-X lib/guardrails.py (deterministic part only: VOICE_PATTERNS,
LEGAL_RE, em-dash > 2) and lib/image_gen.py (PUBLIC_BLOCKED_TOKENS). Source:
nwnwnw413/ChronoAI-Auto-X, Ada's private repo, reused with permission.
Everything that needs an LLM (30s comprehension, claim binding) is left to the
reviewer agents.

Input: an issue body (Markdown with exactly one ```yaml block) or a bare
YAML/JSON item package, schema autox-item/v0.2.
Output: JSON on stdout: per-variant hits, eligible flags, char_count, sha12, and
the studio decision (ok -> checked, revise -> revise with round+1,
skip -> done:skipped rework_exhausted).
--write-body (skill 0.4) also appends one row to the append-only `history` and, on
skip, writes `outcome: {state: skipped, reason_code: rework_exhausted, at}`.
Exit: 0 = at least one variant eligible (decision ok), 1 = no eligible variant,
2 = unreadable input.

  guardrails.py body.md
  guardrails.py body.md --write-body new_body.md [--image '{"path": ...}'] [--at 2026-11-17T09:01+08:00]
  guardrails.py --text "Line one. Line two." --mode image_text
"""
from __future__ import annotations

import argparse
import json
import hashlib
import re
import sys
import unicodedata
from pathlib import Path

ASSETS = Path(__file__).resolve().parents[1] / "assets"
SCHEMA = "autox-item/v0.2"
OUTPUT_SCHEMA = "autox-guardrails/v0.2.1"
CONTENT_TYPES = {"regular", "release"}          # newsjack, x_reply: P2
MAX_ROUND = 2
LENGTH_LIMIT = {"release": 280}
DEFAULT_LIMIT = 240
TCO_LENGTH = 23
HASHTAG_RANGE = {"x_reply": (0, 3)}
DEFAULT_HASHTAG_RANGE = (1, 3)
PRODUCT_NAMES = {"nyxid": ["NyxID"], "ornn": ["Ornn"]}

# ---- ported from Auto-X lib/guardrails.py -------------------------------------------
LEGAL_RE = re.compile(r"(?i)(?:\bbest\b|\bguaranteed\b|#\s*1\b|\bnumber\s+one\b)")
VOICE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("delve", re.compile(r"(?i)\bdelve(?:s|d|ing)?\b")),
    ("seamless", re.compile(r"(?i)\bseamless(?:ly)?\b")),
    ("in_today", re.compile(r"(?i)\bin today['’]s\b")),
    ("worth_noting", re.compile(r"(?i)\bit'?s worth noting\b")),
    ("key_takeaways", re.compile(r"(?i)\bkey takeaways\b")),
    ("in_summary", re.compile(r"(?i)\bin summary\b")),
    ("unlock", re.compile(r"(?i)\bunlock(?:s|ed|ing)?\b")),
    ("leverage", re.compile(r"(?i)\bleverage(?:s|d|ing)?\b")),
    ("robust", re.compile(r"(?i)\brobust\b")),
    ("game_changer", re.compile(r"(?i)\bgame[- ]changer\b")),
    ("not_just_but", re.compile(r"(?i)\bnot just\b.+\bbut\b")),
]
EM_DASH_MAX = 2
# ---- ported from Auto-X lib/image_gen.py PUBLIC_BLOCKED_TOKENS, widened to variants --
INTERNAL_MARKER_RE = re.compile(
    r"(?i)(?:⟦|⟧|AI\s*[:：]\s*AUTO[\s_-]*LOOP|autox-event)")
# ---- new checks -----------------------------------------------------------------------
LINE_REF_RE = re.compile(r"\([\w/-]+\.(rs|py|mjs|ts|js|go|md):\s*L?\d+(-L?\d+)?\)")
URL_RE = re.compile(r"(?i)\bhttps?://[^\s<>\"]+|\bwww\.[^\s<>\"]+")
BARE_DOMAIN_RE = re.compile(
    r"(?i)(?<![@\w.-])(?:[a-z0-9-]+\.)+(?:com|net|org|io|dev|ai|app|sh|fun|xyz|co|me|so|gg|"
    r"link|tech|cloud|site)\b(?:/[^\s]*)?")
HASHTAG_RE = re.compile(r"(?<![\w&#])#(\w+)")
THREAD_EMOJI = "\U0001f9f5"
THREAD_WORD_RE = re.compile(r"(?i)\bthread\s*:")
THREAD_BARE_RE = re.compile(r"(?<![\w/])\(?(\d{1,2})/\)?(?=\s|$)")
# "2/5" only counts at the start or end of a line, so "24/7" and "a 50/50 call" pass.
THREAD_FRACTION_RE = re.compile(
    r"(?m)^\s*\(?(\d{1,2})/(\d{1,2})\)?(?=\s|$)|(?<=\s)\(?(\d{1,2})/(\d{1,2})\)?[ \t]*$")
# Command / install-instruction rules. release.cta is exempt from these (contract v0.2.1 section 9).
COMMAND_RES = [
    ("code_span", re.compile(r"`[^`\n]+`")),
    ("shell_prompt", re.compile(r"(?m)^\s*\$\s+\S")),
    ("install_command", re.compile(
        r"(?i)\b(?:npm|pnpm|yarn|npx|pip3?|pipx|uv|brew|cargo|apt(?:-get)?|go)\s+(?:install|add|get|i)\b"
        r"|\b(?:curl|wget)\b[^\n]*\|\s*(?:ba|z)?sh\b")),
]
INVISIBLE_RE = re.compile("[\u200b\u200c\u200e\u200f\u2060-\u2064\ufeff\u202a-\u202e]")


def _load_json(name: str) -> dict:
    path = ASSETS / name
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def blocked_names() -> list[str]:
    return [row["name"] for row in _load_json("registry.json").get("blocked_names", [])]


def capability_ids() -> dict[str, set[str]]:
    data = _load_json("capability-ids.json").get("products", {})
    return {slug: set(row.get("ids") or []) for slug, row in data.items()}


# ---- parsing --------------------------------------------------------------------------
FENCE_RE = re.compile(r"```ya?ml[^\n]*\n(.*?)\n```", re.S)


def parse_package(raw: str) -> dict:
    blocks = FENCE_RE.findall(raw)
    if len(blocks) > 1:
        raise ValueError(f"issue body has {len(blocks)} yaml blocks; the contract allows exactly one")
    text = blocks[0] if blocks else raw
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(text)
    except ImportError:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("item package is not a mapping")
    return data


# ---- length (X weighted count, twitter-text v3 style) ------------------------------
_LIGHT_RANGES = ((0, 4351), (8192, 8205), (8208, 8223), (8242, 8247))
_ZERO_WIDTH = {0x200D, 0xFE0E, 0xFE0F} | set(range(0x1F3FB, 0x1F400))


def _weight(ch: str) -> int:
    cp = ord(ch)
    if cp in _ZERO_WIDTH:
        return 0
    return 1 if any(a <= cp <= b for a, b in _LIGHT_RANGES) else 2


def find_urls(text: str) -> list[str]:
    urls = [m.group(0).rstrip(".,;:!?)]}") for m in URL_RE.finditer(text)]
    rest = URL_RE.sub(" ", text)
    urls += [m.group(0).rstrip(".,;:!?)]}") for m in BARE_DOMAIN_RE.finditer(rest)]
    return urls


def weighted_length(text: str) -> int:
    """URLs count 23 (t.co); CJK and emoji count 2; other characters count 1."""
    text = unicodedata.normalize("NFC", text)
    total = 0
    for url in find_urls(text):
        if url in text:
            text = text.replace(url, "", 1)
            total += TCO_LENGTH
    return total + sum(_weight(ch) for ch in text)


# ---- checks ---------------------------------------------------------------------------
def _hit(check: str, detail: str) -> dict:
    return {"check": check, "detail": detail}


def _name_re(name: str) -> re.Pattern[str]:
    return re.compile(r"(?i)(?<![\w.])@?" + re.escape(name) + r"(?![\w])")


def sha12(text: str) -> str:
    """Audit digest of the exact variant text (UTF-8), first 12 hex chars."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def check_common(text: str, names: list[str]) -> list[dict]:
    """Checks that apply to post text and to text drawn on an image."""
    hits = []
    dashes = text.count("—")
    if dashes > EM_DASH_MAX:
        hits.append(_hit("em_dash", f"{dashes} em-dashes, limit {EM_DASH_MAX}"))
    for label, pattern in VOICE_PATTERNS:
        m = pattern.search(text)
        if m:
            hits.append(_hit("voice", f"{label}: {m.group(0)!r}"))
    for m in LEGAL_RE.finditer(text):
        hits.append(_hit("legal", f"blocked legal/comparison word {m.group(0)!r}"))
    for m in INTERNAL_MARKER_RE.finditer(text):
        hits.append(_hit("internal_marker", f"internal marker fragment {m.group(0)!r}"))
    for m in LINE_REF_RE.finditer(text):
        hits.append(_hit("line_ref", f"source line reference {m.group(0)!r}"))
    if INVISIBLE_RE.search(text):
        hits.append(_hit("invisible_char", "zero-width or bidi control character present"))
    seen = set()
    for name in names:
        m = _name_re(name).search(text)
        if m and name.lower() not in seen:
            seen.add(name.lower())
            hits.append(_hit("competitor", f"names a competitor: {m.group(0)!r}"))
    return hits


def check_commands(text: str) -> list[dict]:
    hits = []
    for label, pattern in COMMAND_RES:
        m = pattern.search(text)
        if m:
            hits.append(_hit("command", f"{label}: {m.group(0)!r}"))
    return hits


def check_thread(text: str) -> list[dict]:
    hits = []
    if THREAD_EMOJI in text:
        hits.append(_hit("thread_marker", "thread emoji"))
    if THREAD_WORD_RE.search(text):
        hits.append(_hit("thread_marker", "'Thread:' label"))
    for m in THREAD_BARE_RE.finditer(text):
        hits.append(_hit("thread_marker", f"thread numbering {m.group(0).strip()!r}"))
    for m in THREAD_FRACTION_RE.finditer(text):
        num, den = [int(g) for g in m.groups() if g is not None]
        if 1 <= num <= den <= 25:
            hits.append(_hit("thread_marker", f"thread numbering {m.group(0).strip()!r}"))
    return hits


def check_variant(variant: dict, product: str, content_type: str, names: list[str],
                  cta: str | None = None, url: str | None = None) -> dict:
    """Contract v0.2.1 section 9: a release post ends with release.cta and then release.url
    (hashtags may sit before or after). The cta text is exempt from the command rules; the
    url text (and the registry URL inside the cta, copied verbatim) is exempt from the URL
    rule. Both still count for length (URLs as 23)."""
    text = str(variant.get("text") or "")
    hits = []
    if not text.strip():
        hits.append(_hit("empty", "variant text is empty"))
    limit = LENGTH_LIMIT.get(content_type, DEFAULT_LIMIT)
    length = weighted_length(text)
    if length > limit:
        hits.append(_hit("length", f"weighted length {length} > {limit} (URLs count {TCO_LENGTH})"))
    own = text
    if content_type == "release" and cta and url:
        tail_re = re.compile(re.escape(cta.strip()) + r"\s+" + re.escape(url.strip()) + r"((?:\s*#\w+)*\s*)$")
        m = tail_re.search(text)
        if not m:
            hits.append(_hit("release_cta",
                             "text must end with release.cta then release.url, verbatim (only hashtags may follow)"))
        else:
            own = text[:m.start()] + " " + m.group(1)
    urls = find_urls(own)
    if urls:
        rule = ("regular post body must not contain URLs" if content_type != "release"
                else "release posts may only carry release.url (and the URL inside release.cta)")
        hits.append(_hit("url", f"{rule}: {urls}"))
    body = HASHTAG_RE.sub(" ", URL_RE.sub(" ", own))
    wanted = PRODUCT_NAMES.get(product, [])
    if wanted and not any(_name_re(n).search(body) for n in wanted):
        hits.append(_hit("product_name",
                         f"{'/'.join(wanted)} must appear in the body (hashtags, release.cta and release.url do not count)"))
    tags = [t for t in HASHTAG_RE.findall(text) if not t.isdigit()]
    lo, hi = HASHTAG_RANGE.get(content_type, DEFAULT_HASHTAG_RANGE)
    if not lo <= len(tags) <= hi:
        hits.append(_hit("hashtags", f"{len(tags)} hashtags, allowed {lo}-{hi}"))
    hits += check_thread(text)
    hits += check_common(text, names)
    hits += check_commands(own)
    return {
        "id": variant.get("id"),
        "hook_style": variant.get("hook_style"),
        "eligible": not hits,
        "char_count": length,
        "limit": limit,
        "writer_char_count": variant.get("char_count"),
        "sha12": sha12(text),
        "hits": hits,
    }


def check_package(pkg: dict, names: list[str], ids: dict[str, set[str]] | None = None) -> list[dict]:
    """Item-level hits. Any item-level hit makes every variant ineligible."""
    ids = capability_ids() if ids is None else ids
    hits = []
    if pkg.get("schema") != SCHEMA:
        hits.append(_hit("schema", f"schema {pkg.get('schema')!r}, expected {SCHEMA!r}"))
    product = str(pkg.get("product") or "")
    if product not in PRODUCT_NAMES:
        hits.append(_hit("product", f"product {product!r} is not an enabled product"))
    content_type = str(pkg.get("content_type") or "")
    if content_type not in CONTENT_TYPES:
        hits.append(_hit("content_type", f"content_type {content_type!r} is not allowed in P1"))
    known = ids.get(product, set())
    pool = list(pkg.get("capability_pool") or [])
    bound = list(pkg.get("capability_ids") or [])
    for cid in pool + bound:
        if known and cid not in known:
            hits.append(_hit("capability_id", f"{cid!r} is not an active {product} capability"))
    if len(bound) > 2:
        hits.append(_hit("capability_id", f"capability_ids binds {len(bound)} ids, at most 2"))
    outside = [c for c in bound if c not in pool]
    if outside:
        hits.append(_hit("capability_id", f"capability_ids not in capability_pool: {outside}"))
    if content_type == "release":
        rel = pkg.get("release")
        cta = rel.get("cta") if isinstance(rel, dict) else None
        if not cta or not str(cta).strip():
            hits.append(_hit("release", "release post needs release.cta"))
        elif "{tag}" in str(cta):
            hits.append(_hit("release", "release.cta still contains the {tag} placeholder"))
        rurl = rel.get("url") if isinstance(rel, dict) else None
        if not rurl or not URL_RE.fullmatch(str(rurl).strip()):
            hits.append(_hit("release", "release post needs release.url (a full http(s) URL)"))
    variants = pkg.get("variants") or []
    vids = [str(v.get("id")) for v in variants if isinstance(v, dict)]
    if sorted(vids) != ["A", "B", "C"]:
        hits.append(_hit("variants", f"expected variants A, B, C; got {vids}"))
    styles = [v.get("hook_style") for v in variants if isinstance(v, dict)]
    if len(set(styles)) != len(styles):
        hits.append(_hit("variants", f"hook_style repeats: {styles}"))
    return hits


def evaluate(pkg: dict, names: list[str], ids: dict[str, set[str]] | None = None) -> dict:
    product = str(pkg.get("product") or "")
    content_type = str(pkg.get("content_type") or "")
    rel = pkg.get("release") if isinstance(pkg.get("release"), dict) else {}
    cta = str(rel.get("cta") or "") or None
    rurl = str(rel.get("url") or "") or None
    item_hits = check_package(pkg, names, ids)
    results = [check_variant(v, product, content_type, names, cta, rurl)
               for v in pkg.get("variants") or [] if isinstance(v, dict)]
    if item_hits:
        for r in results:
            r["eligible"] = False
    eligible = [r["id"] for r in results if r["eligible"]]
    rnd = int(pkg.get("round") or 0)
    if eligible:
        decision = {"verdict": "ok", "reason_code": None, "next_label": "checked", "round_after": rnd}
    elif rnd < MAX_ROUND:
        decision = {"verdict": "revise", "reason_code": "guardrail_fail", "next_label": "revise",
                    "round_after": rnd + 1}
    else:
        decision = {"verdict": "skip", "reason_code": "rework_exhausted", "next_label": "done:skipped",
                    "round_after": rnd, "close": True}
    return {
        "schema": OUTPUT_SCHEMA, "item_schema": pkg.get("schema"), "product": product,
        "content_type": content_type, "round": rnd, "item_hits": item_hits,
        "variants": results, "eligible_variants": eligible, "decision": decision,
        "passed": bool(eligible),
    }


def studio_block(result: dict, at: str) -> dict:
    hits = {r["id"]: [f"{h['check']}: {h['detail']}" for h in r["hits"]]
            for r in result["variants"] if r["hits"]}
    if result["item_hits"]:
        hits["item"] = [f"{h['check']}: {h['detail']}" for h in result["item_hits"]]
    return {"round": result["round"], "verdict": result["decision"]["verdict"],
            "failed_variants": [r["id"] for r in result["variants"] if not r["eligible"]],
            "hits": hits, "at": at}


def history_row(result: dict, at: str, image: dict | None) -> dict:
    """One append-only history row for this studio pass (contract v0.2.1 section 1).
    round is the round that was checked (before any revise bump)."""
    decision = result["decision"]
    reason = decision["reason_code"]
    if decision["verdict"] == "ok" and isinstance(image, dict) and image.get("path") is None:
        reason = "image_fail"
    return {"round": result["round"], "stage": "studio", "verdict": decision["verdict"],
            "reason_code": reason, "at": at}


def apply_to_body(raw: str, pkg: dict, result: dict, at: str, image: dict | None) -> str:
    """Write only studio-owned fields (char_count, sha12, eligible, image, studio) and,
    on revise, round+1. Append one row to `history` (existing rows are never touched) and,
    when the item goes terminal (skip -> done:skipped rework_exhausted), write `outcome`.
    Everything else keeps its value; text outside the yaml block is kept."""
    import yaml  # type: ignore
    history = pkg.get("history")
    if history is None:
        history = []
    if not isinstance(history, list):
        raise ValueError("history must be a list (append-only)")
    if pkg.get("outcome") not in (None, {}):
        raise ValueError("item already has an outcome; a terminal item is not re-checked")
    by_id = {r["id"]: r for r in result["variants"]}
    for v in pkg.get("variants") or []:
        r = by_id.get(v.get("id"))
        if r:
            v["char_count"], v["sha12"], v["eligible"] = r["char_count"], r["sha12"], r["eligible"]
    pkg["studio"] = studio_block(result, at)
    if image is not None:
        pkg["image"] = image
    pkg["round"] = result["decision"]["round_after"]
    pkg["history"] = history + [history_row(result, at, image)]
    if result["decision"]["verdict"] == "skip":
        pkg["outcome"] = {"state": "skipped", "reason_code": result["decision"]["reason_code"], "at": at}
    else:
        pkg.setdefault("outcome", None)
    dumped = yaml.safe_dump(pkg, allow_unicode=True, sort_keys=False, width=10_000).rstrip("\n")
    blocks = list(FENCE_RE.finditer(raw))
    if not blocks:
        return "```yaml\n" + dumped + "\n```\n"
    m = blocks[0]
    return raw[:m.start(1)] + dumped + raw[m.end(1):]


def check_image_text(text: str, names: list[str]) -> dict:
    hits = check_common(text, names) + check_thread(text) + check_commands(text)
    if find_urls(text):
        hits.append(_hit("url", "image text must not contain URLs"))
    return {"schema": OUTPUT_SCHEMA, "mode": "image_text", "passed": not hits, "hits": hits}


def _now_sgt() -> str:
    from datetime import datetime, timedelta, timezone
    return datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%dT%H:%M+08:00")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Auto-X deterministic guardrails (contract v0.2.1)")
    ap.add_argument("path", nargs="?", help="issue body / YAML package file, or - for stdin")
    ap.add_argument("--text", help="check a bare string (image text) instead of a package")
    ap.add_argument("--mode", choices=["image_text"], default="image_text")
    ap.add_argument("--write-body", type=Path, help="write the updated issue body here")
    ap.add_argument("--image", help="JSON for the image field, written with --write-body")
    ap.add_argument("--at", help="timestamp for studio.at (default: now, +08:00)")
    args = ap.parse_args(argv)
    names = blocked_names()
    try:
        if args.text is not None:
            result = check_image_text(args.text, names)
        else:
            if not args.path:
                ap.error("give a package path, - for stdin, or --text")
            raw = sys.stdin.read() if args.path == "-" else Path(args.path).read_text(encoding="utf-8")
            pkg = parse_package(raw)
            result = evaluate(pkg, names)
            if args.write_body:
                image = json.loads(args.image) if args.image else None
                args.write_body.write_text(apply_to_body(raw, pkg, result, args.at or _now_sgt(), image),
                                           encoding="utf-8")
                result["body_written"] = str(args.write_body)
    except (OSError, ValueError) as exc:
        print(json.dumps({"schema": OUTPUT_SCHEMA, "passed": False, "error": str(exc)}, ensure_ascii=False))
        return 2
    except Exception as exc:  # yaml errors and the like
        print(json.dumps({"schema": OUTPUT_SCHEMA, "passed": False,
                          "error": f"{type(exc).__name__}: {exc}"}, ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=1))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
