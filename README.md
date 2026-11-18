# autox-studio-scripts

Deterministic pre-review checks for the NyxBot edition of Auto-X. The `x-studio` NyxBot specialist runs these inside Chrono Sandbox: it downloads `scripts/guardrails.py` and `assets/*.json` at a pinned commit, verifies their sha256, and runs them on one issue body passed in through an environment variable.

- `scripts/guardrails.py`: length (t.co links count as 23), banned phrases, em-dash count, internal markers, competitor names, thread markers, hashtags, product name, URLs, and (contract v1.3) question openers, template openers, self-answered reveals, contrast reveals, engagement bait and emoji count. Some patterns are adapted from MIT-licensed sources: coreyhaines31/marketingskills (Copyright (c) 2025 Corey Haines; its ai-tells list is itself adapted in part from retieedra-profound/skills-marketing-library, Copyright (c) 2026 Profound), sergebulaev/skills x-post-writer (Copyright (c) 2026 Sergey Bulaev) and blader/humanizer (Copyright (c) 2025 Siqi Chen). Outputs JSON; `--write-body` writes the updated issue body.
- `assets/registry.json`: product registry and names that must not appear in posts.
- `assets/capability-ids.json`: valid capability ids per product.

Contains no credentials. Source of truth is the `autox-studio` Ornn skill; this repo is a pinned copy.

License: MIT.
