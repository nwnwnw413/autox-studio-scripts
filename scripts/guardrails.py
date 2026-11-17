#!/usr/bin/env python3
"""Deterministic pre-review checks for one Auto-X item (NyxBot edition, contract v0.8).

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
Contract v0.4 (skill 0.6): human edits ("human_revise") also bump round but do not
count toward the 2-round rework limit. auto_rounds = round - (history rows whose
reason_code is human_revise); rework is exhausted when auto_rounds >= 2.
--write-body (skill 0.4) also appends one row to the append-only `history` and, on
skip, writes `outcome: {state: skipped, reason_code: rework_exhausted, at}`.
Contract v0.7 (skill 1.0): the image is drawn by the state repo's GitHub Action, not by
the studio. Without --image, --write-body keeps whatever `image` the body already has
(the Action may have written it). The writer's new `image_title` gets item-level checks
(<= 6 words, <= 48 chars, English characters only, no URL/#/@, plus the common checks);
a missing or empty image_title is not a hit (no image for this item).
Contract v0.8 (skill 1.2): the writer's `image_concept` {format, scene, text_on_image, brand}
replaces image_title and gets item-level checks (section 14.3): format in the catalogue
(IMAGE_FORMATS, same ids as the state repo's scripts/image_styles.yaml), brand derived from the
item, scene <= 300 English characters, text_on_image empty or <= 5 words / 40 characters, no
product or competitor names, URLs, #/@, key-like strings, red-line words or the common checks, and
the scene must not ask for a logo, blank space or a screenshot. A missing image_concept is not a
hit; a legacy image_title keeps the v0.7 checks.
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
OUTPUT_SCHEMA = "autox-guardrails/v0.8"
CONTENT_TYPES = {"regular", "release"}          # newsjack, x_reply: P2
MAX_ROUND = 2                                   # max automatic rework rounds (human_revise excluded)
HUMAN_REVISE = "human_revise"
LENGTH_LIMIT = {"release": 280}
DEFAULT_LIMIT = 240
TCO_LENGTH = 23
HASHTAG_RANGE = {"x_reply": (0, 3)}
DEFAULT_HASHTAG_RANGE = (1, 3)
PRODUCT_NAMES = {"nyxid": ["NyxID"], "ornn": ["Ornn"]}
IMAGE_TITLE_MAX_WORDS = 6
IMAGE_TITLE_MAX_CHARS = 48
# ---- contract v0.8 section 14.3: image_concept ----------------------------------------
# format id -> rule for text_on_image ("two_words": left/right panel labels; "required"; "optional")
IMAGE_FORMATS = {"before_after": "two_words", "editorial_flat": "optional", "clay_diorama": "optional",
                 "meme_caption": "required", "pixel_art": "optional", "split_contrast": "optional"}
IMAGE_CONCEPT_KEYS = ("format", "scene", "text_on_image", "brand")
IMAGE_SCENE_MAX_CHARS = 300
IMAGE_TEXT_MAX_WORDS = 5
IMAGE_TEXT_MAX_CHARS = 40
OWN_NAMES = ["NyxID", "NyxBot", "ChronoAI", "Chrono AI", "Ornn"]     # the logo is pasted by the Action
REDLINE_RE = re.compile(r"(?i)\b(?:math|maths|mathematics|mathematical|theorems?|trureturing|olympiad|sair|"
                        r"proof assistant|formal proofs?)\b|\bLean(?:\s?4)?\b")
SECRET_RE = re.compile(r"(?i)\b(?:sk|pk|rk|ghp|gho|ghs|xox[abp]|nyx)[-_][A-Za-z0-9]|\b(?=[\w-]*\d)[A-Za-z0-9_\-]{20,}")
SCENE_LAYOUT_RE = re.compile(r"(?i)\b(?:logos?|wordmarks?|brand ?marks?|copy[- ]space|screenshots?|"
                             r"blank (?:area|space|box|corner|panel)|empty (?:area|space|box|corner) for|"
                             r"leave (?:room|space))\b")
# English characters only: printable ASCII plus curly quotes; '#' and '@' are rejected separately.
IMAGE_TITLE_CHARS_RE = re.compile("[ -~\u2018\u2019\u201c\u201d]+")

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


def check_image_title(title, names: list[str]) -> list[dict]:
    """Contract v0.7 section 14.3: the writer's one-per-item image title. Empty/missing -> no hits."""
    if title is None:
        return []
    if not isinstance(title, str):
        return [_hit("image_title", f"image_title must be a string, got {type(title).__name__}")]
    text = title.strip()
    if not text:
        return []
    hits = []
    words = text.split()
    if len(words) > IMAGE_TITLE_MAX_WORDS:
        hits.append(_hit("image_title", f"{len(words)} words, limit {IMAGE_TITLE_MAX_WORDS}"))
    if len(text) > IMAGE_TITLE_MAX_CHARS:
        hits.append(_hit("image_title", f"{len(text)} characters, limit {IMAGE_TITLE_MAX_CHARS}"))
    if not IMAGE_TITLE_CHARS_RE.fullmatch(text):
        bad = sorted({ch for ch in text if not IMAGE_TITLE_CHARS_RE.fullmatch(ch)})
        hits.append(_hit("image_title", f"English characters only, found {bad}"))
    if "#" in text or "@" in text:
        hits.append(_hit("image_title", "no hashtags or @handles on the image"))
    if find_urls(text):
        hits.append(_hit("image_title", "no URLs on the image"))
    for h in check_common(text, names):
        hits.append(_hit("image_title", f"{h['check']}: {h['detail']}"))
    return hits


def derive_brand(pkg: dict) -> str | None:
    """Contract v0.8 section 14.3: company content -> chronoai, otherwise the item's product."""
    cal = pkg.get("calendar")
    if isinstance(cal, dict) and cal.get("product") == "company":
        return "chronoai"
    product = str(pkg.get("product") or "")
    return product if product in PRODUCT_NAMES else None


def _image_words(text: str, label: str, names: list[str]) -> list[dict]:
    """Checks shared by scene and text_on_image."""
    hits = []
    if not IMAGE_TITLE_CHARS_RE.fullmatch(text):
        bad = sorted({ch for ch in text if not IMAGE_TITLE_CHARS_RE.fullmatch(ch)})
        hits.append(_hit("image_concept", f"{label}: English characters only, found {bad}"))
    if "#" in text or "@" in text:
        hits.append(_hit("image_concept", f"{label}: no hashtags or @handles"))
    if find_urls(text):
        hits.append(_hit("image_concept", f"{label}: no URLs"))
    for name in OWN_NAMES:
        if _name_re(name).search(text):
            hits.append(_hit("image_concept", f"{label}: product name {name!r} (the Action pastes the official logo)"))
            break
    m = REDLINE_RE.search(text)
    if m:
        hits.append(_hit("image_concept", f"{label}: red-line word {m.group(0)!r}"))
    m = SECRET_RE.search(text)
    if m:
        hits.append(_hit("image_concept", f"{label}: looks like a key or token {m.group(0)!r}"))
    for h in check_common(text, names):
        hits.append(_hit("image_concept", f"{label}: {h['check']}: {h['detail']}"))
    return hits


def check_image_concept(concept, names: list[str], pkg: dict) -> list[dict]:
    """Contract v0.8 section 14.3: the writer's one-per-item image concept. Missing/null -> no hits."""
    if concept is None:
        return []
    if not isinstance(concept, dict):
        return [_hit("image_concept", f"image_concept must be a mapping, got {type(concept).__name__}")]
    hits = []
    missing = [k for k in IMAGE_CONCEPT_KEYS if k not in concept]
    if missing:
        hits.append(_hit("image_concept", f"missing keys {missing}"))
    fmt = concept.get("format")
    if fmt not in IMAGE_FORMATS:
        hits.append(_hit("image_concept", f"format {fmt!r} is not in the catalogue {sorted(IMAGE_FORMATS)}"))
    brand = derive_brand(pkg)
    if concept.get("brand") != brand:
        hits.append(_hit("image_concept", f"brand {concept.get('brand')!r}, expected {brand!r} from the item"))
    scene = concept.get("scene")
    if not isinstance(scene, str) or not scene.strip():
        hits.append(_hit("image_concept", "scene must be a non-empty English sentence"))
    else:
        scene = " ".join(scene.split())
        if len(scene) > IMAGE_SCENE_MAX_CHARS:
            hits.append(_hit("image_concept", f"scene: {len(scene)} characters, limit {IMAGE_SCENE_MAX_CHARS}"))
        m = SCENE_LAYOUT_RE.search(scene)
        if m:
            hits.append(_hit("image_concept", f"scene: do not ask for {m.group(0)!r} (logo and layout are the Action's job)"))
        hits += _image_words(scene, "scene", names)
    text = concept.get("text_on_image")
    if text is not None and not isinstance(text, str):
        hits.append(_hit("image_concept", "text_on_image must be a string or null"))
        text = None
    text = " ".join((text or "").split())
    words = text.split()
    if len(words) > IMAGE_TEXT_MAX_WORDS:
        hits.append(_hit("image_concept", f"text_on_image: {len(words)} words, limit {IMAGE_TEXT_MAX_WORDS}"))
    if len(text) > IMAGE_TEXT_MAX_CHARS:
        hits.append(_hit("image_concept", f"text_on_image: {len(text)} characters, limit {IMAGE_TEXT_MAX_CHARS}"))
    rule = IMAGE_FORMATS.get(fmt)
    if rule == "two_words" and len(words) != 2:
        hits.append(_hit("image_concept", f"text_on_image: {fmt} needs exactly two words (left and right labels)"))
    if rule == "required" and not words:
        hits.append(_hit("image_concept", f"text_on_image: {fmt} needs the caption"))
    if text:
        hits += _image_words(text, "text_on_image", names)
    return hits


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
    hits += check_image_title(pkg.get("image_title"), names)
    hits += check_image_concept(pkg.get("image_concept"), names, pkg)
    return hits


def human_revisions(pkg: dict) -> int:
    """Rows in the append-only history written when Ada asked for an edit (contract v0.4)."""
    history = pkg.get("history")
    if not isinstance(history, list):
        return 0
    return sum(1 for row in history if isinstance(row, dict) and row.get("reason_code") == HUMAN_REVISE)


def auto_rounds(pkg: dict) -> int:
    """Automatic rework rounds so far: round minus human-requested rewrites (never below 0)."""
    return max(0, int(pkg.get("round") or 0) - human_revisions(pkg))


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
    auto = auto_rounds(pkg)
    if eligible:
        decision = {"verdict": "ok", "reason_code": None, "next_label": "checked", "round_after": rnd}
    elif auto < MAX_ROUND:
        decision = {"verdict": "revise", "reason_code": "guardrail_fail", "next_label": "revise",
                    "round_after": rnd + 1}
    else:
        decision = {"verdict": "skip", "reason_code": "rework_exhausted", "next_label": "done:skipped",
                    "round_after": rnd, "close": True}
    return {
        "schema": OUTPUT_SCHEMA, "item_schema": pkg.get("schema"), "product": product,
        "content_type": content_type, "round": rnd, "auto_rounds": auto,
        "human_revisions": human_revisions(pkg), "item_hits": item_hits,
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
    """Write only studio-owned fields (char_count, sha12, eligible, studio) and,
    on revise, round+1. Append one row to `history` (existing rows are never touched) and,
    when the item goes terminal (skip -> done:skipped rework_exhausted), write `outcome`.
    Everything else keeps its value; text outside the yaml block is kept.
    Contract v0.7: `image` belongs to the image Action. It is only replaced when the
    caller passes --image explicitly; otherwise the body's value is written back as is."""
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
    ap = argparse.ArgumentParser(description="Auto-X deterministic guardrails (contract v0.8)")
    ap.add_argument("path", nargs="?", help="issue body / YAML package file, or - for stdin")
    ap.add_argument("--text", help="check a bare string (image text) instead of a package")
    ap.add_argument("--mode", choices=["image_text"], default="image_text")
    ap.add_argument("--write-body", type=Path, help="write the updated issue body here")
    ap.add_argument("--image", help="JSON for the image field, written with --write-body "
                    "(omit it to keep the body's image as is; contract v0.7)")
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
