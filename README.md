# autox-studio-scripts

Deterministic pre-review checks for the NyxBot edition of Auto-X. The `x-studio` NyxBot specialist runs these inside Chrono Sandbox: it downloads `scripts/guardrails.py` and `assets/*.json` at a pinned commit, verifies their sha256, and runs them on one issue body passed in through an environment variable.

- `scripts/guardrails.py`: length (t.co links count as 23), banned phrases, em-dash count, internal markers, competitor names, thread markers, hashtags, product name, URLs. Outputs JSON; `--write-body` writes the updated issue body.
- `assets/registry.json`: product registry and names that must not appear in posts.
- `assets/capability-ids.json`: valid capability ids per product.

Contains no credentials. Source of truth is the `autox-studio` Ornn skill; this repo is a pinned copy.

License: MIT.
