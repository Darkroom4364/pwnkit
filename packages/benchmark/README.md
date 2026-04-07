# @pwnkit/benchmark

Benchmark runners for pwnkit across multiple security evaluation suites
(XBOW, AutoPenBench, CyBench, HarmBench, NPM advisories).

This document focuses on the **XBOW runner** and how to point it at
arbitrary XBOW-compatible benchmark suites.

## XBOW runner

The XBOW runner (`src/xbow-runner.ts`, exposed as `pnpm xbow`) executes
pwnkit against the [XBOW validation benchmarks][xbow] — 104 Docker CTF
challenges covering SQLi, XSS, SSRF, deserialization, IDOR, auth bypass,
command injection, and other classic web bug classes.

[xbow]: https://github.com/xbow-engineering/validation-benchmarks

### Benchmark source precedence

The runner locates the benchmark suite on disk using the following
precedence (first match wins):

1. `--benchmark-path <dir>` — use an existing local checkout as-is
2. `XBOW_PATH` environment variable — use an existing local checkout as-is
3. `--benchmark-repo <git-url>` — clone into a workspace cache dir
   (`$TMPDIR/pwnkit-xbow-cache/<slug>`) and reuse the clone on subsequent
   runs
4. Default `/tmp/xbow-benchmarks`

`--benchmark-repo` accepts either the GitHub short form (`owner/repo`)
or a full git URL (`https://github.com/owner/repo.git`, SSH specs, etc.).
Use `--benchmark-ref <branch|tag|sha>` to pin a specific ref.

### Examples

Run against upstream XBOW (note: several Docker builds are broken upstream):

```sh
pnpm --filter @pwnkit/benchmark xbow \
  --benchmark-repo xbow-engineering/validation-benchmarks \
  --agentic --limit 10
```

Run against the community patched fork (fixes all 104 Docker builds):

```sh
pnpm --filter @pwnkit/benchmark xbow \
  --benchmark-repo 0ca/xbow-validation-benchmarks-patched \
  --agentic
```

Run against Shannon's "cleaned" fork (strips comments, variable names,
filepaths, and rewrites Dockerfiles — the substrate Shannon used for
their 96.15% result):

```sh
pnpm --filter @pwnkit/benchmark xbow \
  --benchmark-repo KeygraphHQ/xbow-validation-benchmarks \
  --agentic
```

Use a local checkout without cloning:

```sh
pnpm --filter @pwnkit/benchmark xbow \
  --benchmark-path /path/to/my/xbow-fork \
  --agentic --limit 5
```

### CI (GitHub Actions)

The `.github/workflows/xbow-bench.yml` workflow exposes two
`workflow_dispatch` inputs that drive the same behavior:

- `benchmark_repo` — any XBOW-compatible source repo
  (default: `0ca/xbow-validation-benchmarks-patched`)
- `benchmark_ref` — optional branch/tag/sha inside that repo

The clone step in the workflow honors these inputs before any benchmark
runs, so scheduled and dispatched runs can easily target upstream, the
patched fork, or a cleaned fork for apples-to-apples comparisons.

### Other flags

See the header comment in `src/xbow-runner.ts` for the full flag list
(`--agentic`, `--white-box`, `--limit`, `--tag`, `--level`, `--only`,
`--start`, `--retries`, `--models`, `--fresh`, `--save-findings`,
`--runtime`, `--dry-run`, `--json`).
