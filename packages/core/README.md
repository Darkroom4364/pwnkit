# @pwnkit/core

Engine package for pwnkit: tool definitions, agent loop, playbooks, runtimes,
audit pipeline, and triage filters. Consumed by `@pwnkit/cli`.

## Feature flags

Feature flags are declared in `src/agent/features.ts`. Each flag maps to a
`PWNKIT_FEATURE_<NAME>` environment variable. The `@pwnkit/cli` `scan` command
also accepts a `--features` flag that sets those env vars automatically:

```bash
pnpm pwnkit scan --target https://example.com --features wp_fingerprint
pnpm pwnkit scan --target https://example.com --features wp_fingerprint,web_search
```

Any token passed to `--features` is upcased, non-alphanumeric chars are
replaced with `_`, and the result is set as `PWNKIT_FEATURE_<TOKEN>=1`. For
most flags the value is captured at module-import time — setting env vars in
your shell is the most reliable approach. Flags that are declared as getters
(e.g. `wpFingerprint`) re-read the env at access time and therefore honour
`--features` even though the flag is applied inside the command action.

## Playbooks

Playbooks live in `src/agent/playbooks.ts`. Each playbook is a string keyed by
vulnerability type (`sqli`, `ssti`, `idor`, `xss`, `cve_exploitation`, …) plus
a set of regex `INDICATORS` that pattern-match against recent tool-result text.
When `PWNKIT_FEATURE_DYNAMIC_PLAYBOOKS=1`, the native agent loop matches
indicators at ~30% of the turn budget and injects the top 3 matching playbooks
as a user message.

## WordPress fingerprinter (`wp_fingerprint`)

Opt-in tool exposed behind the `wp_fingerprint` feature flag. Implemented in
`src/agent/wp-fingerprint.ts`.

### What it does

1. **Detects WordPress** by fetching `wp-login.php`, `wp-admin/`, `readme.html`,
   `wp-includes/version.php`, `feed/`, and `wp-json/`. Extracts the core
   version from `wp-includes/version.php` (authoritative), `readme.html`, or
   the RSS feed's `<generator>` tag.
2. **Enumerates plugins** from four independent sources in parallel:
   - Rendered HTML on `/`, `/?p=1`, `/?page_id=1` (any `/wp-content/plugins/<slug>/…` URL in asset tags)
   - `/wp-json/` namespace index and `/wp-json/wp/v2/posts` rendered content
   - `/wp-content/plugins/` Apache/nginx autoindex listings
3. **Enumerates themes** the same way.
4. **Probes versions** by fetching each plugin's `readme.txt` (parsing the
   `Stable tag:` header) and each theme's `style.css` (parsing the `Version:`
   header). Both are WordPress conventions and ship with nearly every
   plugin/theme on wordpress.org.
5. **Looks up CVEs** by POSTing each `(slug, version)` pair to
   `https://api.osv.dev/v1/query`. OSV's wpvulndb/Patchstack imports surface
   most published WordPress plugin CVEs.
6. **Returns structured findings** — a list of `(kind, slug, version, cves, exploit_hints)`
   tuples plus a human-readable summary the agent can act on.

### CLI usage

```bash
pnpm pwnkit scan \
  --target https://wordpress-target.example.com \
  --features wp_fingerprint
```

### Tool invocation (from the agent)

```json
{
  "name": "wp_fingerprint",
  "arguments": { "max_plugin_probes": 40, "skip_osv": false }
}
```

### Sample output (structured)

```json
{
  "summary": "WordPress detected — core v6.1. Evidence: wp-login.php, readme.html\nPlugins: 2, Themes: 1\n\nCVE hits (1):\n  - [plugin] contact-form-7@5.3.1: CVE-2020-35489\n      hint: Try unauthenticated file upload against /wp-content/plugins/contact-form-7/ endpoints — check the CVE advisory for the exact path.",
  "result": {
    "isWordPress": true,
    "evidence": ["wp-login.php", "readme.html"],
    "coreVersion": "6.1",
    "plugins": [
      { "slug": "contact-form-7", "version": "5.3.1", "source": "readme" },
      { "slug": "woocommerce", "version": "4.0.0", "source": "readme" }
    ],
    "themes": [
      { "slug": "twentytwentyone", "version": "1.7.1", "source": "style_css" }
    ],
    "findings": [
      {
        "kind": "plugin",
        "slug": "contact-form-7",
        "version": "5.3.1",
        "source": "readme",
        "cves": [
          {
            "id": "CVE-2020-35489",
            "aliases": ["GHSA-..."],
            "severity": "critical",
            "summary": "Unrestricted file upload in Contact Form 7 < 5.3.2",
            "url": "https://osv.dev/vulnerability/CVE-2020-35489"
          }
        ],
        "exploitHints": [
          "Try unauthenticated file upload against /wp-content/plugins/contact-form-7/ endpoints — check the CVE advisory for the exact path."
        ]
      }
    ]
  }
}
```

### Tests

```bash
pnpm --filter @pwnkit/core test -- wp-fingerprint
```

The test suite (`src/agent/wp-fingerprint.test.ts`) mocks `fetch` with an
in-memory route table and exercises: plugin slug extraction, `readme.txt`
version parsing, `style.css` version parsing, the full end-to-end
`runWpFingerprint` with `skipOsv: true`, and the negative case where no WP
endpoints respond. Tests never hit the network.
