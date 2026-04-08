import { execFileSync, execSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import type { NpmAuditFinding, Severity } from "@pwnkit/shared";
import type { ScanListener } from "./scanner.js";
import { restoreHistoricalPackageFixture, shouldUseHistoricalPackageFallback } from "./historical-package-fallback.js";
import { bufferToString } from "./shared-analysis.js";

export type PackageEcosystem = "npm" | "pypi" | "cargo";

export interface InstalledPackage {
  ecosystem: PackageEcosystem;
  name: string;
  version: string;
  path: string;
  tempDir: string;
}

export function normalizeSeverity(value: string | undefined): Severity {
  switch ((value ?? "").toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "moderate":
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      return "info";
  }
}

export function formatFixAvailable(
  fixAvailable: boolean | { name?: string; version?: string } | string | undefined,
): boolean | string {
  if (typeof fixAvailable === "string" || typeof fixAvailable === "boolean") {
    return fixAvailable;
  }
  if (fixAvailable && typeof fixAvailable === "object") {
    const next = [fixAvailable.name, fixAvailable.version].filter(Boolean).join("@");
    return next || true;
  }
  return false;
}

export function parseNpmAuditOutput(rawOutput: string): NpmAuditFinding[] {
  if (!rawOutput.trim()) return [];

  try {
    const raw = JSON.parse(rawOutput) as {
      vulnerabilities?: Record<
        string,
        {
          name?: string;
          severity?: string;
          via?: Array<string | Record<string, unknown>>;
          range?: string;
          fixAvailable?: boolean | { name?: string; version?: string } | string;
        }
      >;
    };

    return Object.entries(raw.vulnerabilities ?? {}).map(([pkgName, vuln]) => {
      const via = (vuln.via ?? []).map((entry) => {
        if (typeof entry === "string") return entry;
        const source = typeof entry.source === "number" ? `GHSA:${entry.source}` : null;
        const title = typeof entry.title === "string" ? entry.title : null;
        const name = typeof entry.name === "string" ? entry.name : null;
        return [name, title, source].filter(Boolean).join(" - ") || "unknown advisory";
      });

      const firstObjectVia = (vuln.via ?? []).find(
        (entry): entry is Record<string, unknown> => typeof entry === "object" && entry !== null,
      );

      return {
        name: vuln.name ?? pkgName,
        severity: normalizeSeverity(vuln.severity),
        title:
          (typeof firstObjectVia?.title === "string" && firstObjectVia.title) ||
          via[0] ||
          "npm audit advisory",
        range: vuln.range,
        source:
          typeof firstObjectVia?.source === "number" || typeof firstObjectVia?.source === "string"
            ? (firstObjectVia.source as number | string)
            : undefined,
        url: typeof firstObjectVia?.url === "string" ? firstObjectVia.url : undefined,
        via,
        fixAvailable: formatFixAvailable(vuln.fixAvailable),
      };
    });
  } catch {
    return [];
  }
}

function parsePipAuditOutput(rawOutput: string): NpmAuditFinding[] {
  if (!rawOutput.trim()) return [];

  try {
    const parsed = JSON.parse(rawOutput) as {
      dependencies?: Array<{
        name?: string;
        version?: string;
        vulns?: Array<{ id?: string; description?: string; aliases?: string[] }>;
      }>;
    };

    const findings: NpmAuditFinding[] = [];
    for (const dep of parsed.dependencies ?? []) {
      for (const vuln of dep.vulns ?? []) {
        const id = String(vuln.id ?? "");
        if (!/^(CVE-|GHSA-)/i.test(id)) continue;
        findings.push({
          name: String(dep.name ?? "unknown"),
          severity: "high",
          title: String(vuln.description ?? vuln.id ?? "pip-audit advisory"),
          range: dep.version,
          source: id,
          url: typeof vuln.aliases?.[0] === "string" ? vuln.aliases[0] : undefined,
          via: [id],
          fixAvailable: false,
        });
      }
    }
    return findings;
  } catch {
    return [];
  }
}

function severityFromCvssScore(score: number | undefined): Severity {
  if (typeof score !== "number" || !Number.isFinite(score)) return "high";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "info";
}

function parseCargoAuditOutput(rawOutput: string): NpmAuditFinding[] {
  if (!rawOutput.trim()) return [];

  try {
    const parsed = JSON.parse(rawOutput) as {
      vulnerabilities?: {
        list?: Array<{
          package?: { name?: string; version?: string };
          advisory?: {
            id?: string;
            title?: string;
            aliases?: string[];
            url?: string;
            cvss?: number;
          };
          versions?: { patched?: string[] };
        }>;
      };
    };

    return (parsed.vulnerabilities?.list ?? []).map((entry) => {
      const aliases = entry.advisory?.aliases ?? [];
      const source = entry.advisory?.id ?? aliases[0];
      return {
        name: String(entry.package?.name ?? "unknown"),
        severity: severityFromCvssScore(entry.advisory?.cvss),
        title: String(entry.advisory?.title ?? entry.advisory?.id ?? "cargo audit advisory"),
        range: entry.package?.version,
        source,
        url: entry.advisory?.url,
        via: [source, ...aliases].filter(Boolean) as string[],
        fixAvailable: entry.versions?.patched?.[0] ?? false,
      };
    });
  } catch {
    return [];
  }
}

function splitPackageSpec(rawPackageName: string, requestedVersion: string | undefined): {
  packageName: string;
  version: string | undefined;
} {
  let packageName = rawPackageName;
  let version = requestedVersion;
  const atIdx = rawPackageName.startsWith("@")
    ? rawPackageName.indexOf("@", 1)
    : rawPackageName.indexOf("@");
  if (atIdx > 0) {
    packageName = rawPackageName.slice(0, atIdx);
    version = version ?? rawPackageName.slice(atIdx + 1);
  }
  return { packageName, version };
}

function writeMinimalPackageJson(tempDir: string): void {
  execFileSync("npm", ["init", "-y", "--silent"], {
    cwd: tempDir,
    timeout: 15_000,
    stdio: "pipe",
  });
}

function restoreNpmFixtureOrThrow(
  packageName: string,
  tempDir: string,
  msg: string,
  emit: ScanListener,
): InstalledPackage | never {
  if (shouldUseHistoricalPackageFallback(msg)) {
    const restored = restoreHistoricalPackageFixture(packageName, tempDir, emit);
    if (restored) {
      return {
        ecosystem: "npm",
        ...restored,
        tempDir,
      };
    }
  }
  rmSync(tempDir, { recursive: true, force: true });
  throw new Error(msg);
}

function installNpmPackage(
  packageName: string,
  requestedVersion: string | undefined,
  emit: ScanListener,
): InstalledPackage {
  const tempDir = join(tmpdir(), `pwnkit-audit-${randomUUID().slice(0, 8)}`);
  mkdirSync(tempDir, { recursive: true });

  const spec = requestedVersion ? `${packageName}@${requestedVersion}` : `${packageName}@latest`;
  emit({ type: "stage:start", stage: "discovery", message: `Installing ${spec}...` });

  try {
    writeMinimalPackageJson(tempDir);
    execFileSync("npm", ["install", spec, "--ignore-scripts", "--no-audit", "--no-fund"], {
      cwd: tempDir,
      timeout: 120_000,
      stdio: "pipe",
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return restoreNpmFixtureOrThrow(packageName, tempDir, `Failed to install ${spec}: ${msg}`, emit);
  }

  const pkgJsonPath = join(tempDir, "node_modules", packageName, "package.json");
  if (!existsSync(pkgJsonPath)) {
    rmSync(tempDir, { recursive: true, force: true });
    throw new Error(`Package ${packageName} not found after install. Check the package name.`);
  }

  const pkgJson = JSON.parse(readFileSync(pkgJsonPath, "utf8"));
  const installedVersion = pkgJson.version as string;
  const packagePath = join(tempDir, "node_modules", packageName);

  emit({ type: "stage:end", stage: "discovery", message: `Installed ${packageName}@${installedVersion}` });
  return {
    ecosystem: "npm",
    name: packageName,
    version: installedVersion,
    path: packagePath,
    tempDir,
  };
}

function extractSingleArchive(archivePath: string, outputDir: string): void {
  execFileSync(
    "python3",
    ["-c", `
import pathlib, tarfile, zipfile, sys
archive = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
name = archive.name
if name.endswith((".whl", ".zip")):
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(out)
else:
    with tarfile.open(archive) as tf:
        tf.extractall(out)
`, archivePath, outputDir],
    { stdio: "pipe", timeout: 60_000 },
  );
}

function pickPythonScopePath(extractRoot: string): string {
  const entries = readdirSync(extractRoot)
    .map((name) => join(extractRoot, name))
    .filter((abs) => existsSync(abs) && statSync(abs).isDirectory());
  return entries.length === 1 ? entries[0]! : extractRoot;
}

function readPythonVersionFromMetadata(scopePath: string): string | undefined {
  const candidates: string[] = [];
  const stack = [scopePath];

  while (stack.length > 0) {
    const current = stack.pop()!;
    let entries: string[] = [];
    try {
      entries = readdirSync(current);
    } catch {
      continue;
    }
    for (const entry of entries) {
      const abs = join(current, entry);
      let st;
      try {
        st = statSync(abs);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        if (entry.endsWith(".dist-info")) {
          candidates.push(join(abs, "METADATA"));
        } else {
          stack.push(abs);
        }
      } else if (entry === "PKG-INFO") {
        candidates.push(abs);
      }
    }
  }

  for (const metadataPath of candidates) {
    if (!existsSync(metadataPath)) continue;
    const content = readFileSync(metadataPath, "utf8");
    const match = content.match(/^Version:\s*(.+)$/m);
    if (match?.[1]) return match[1].trim();
  }

  return undefined;
}

function readPythonVersionFromArchiveName(packageName: string, archivePath: string): string | undefined {
  const filename = archivePath.split("/").pop() ?? "";
  const stem = filename.replace(/\.(?:tar\.gz|zip|whl)$/i, "");
  const normalized = packageName.replace(/-/g, "_");
  for (const prefix of [`${packageName}-`, `${normalized}-`]) {
    if (!stem.startsWith(prefix)) continue;
    const rest = stem.slice(prefix.length);
    const version = rest.split("-")[0];
    if (version) return version;
  }
  return undefined;
}

function installPypiPackage(
  packageName: string,
  requestedVersion: string | undefined,
  emit: ScanListener,
): InstalledPackage {
  const tempDir = join(tmpdir(), `pwnkit-audit-${randomUUID().slice(0, 8)}`);
  const downloadDir = join(tempDir, "downloads");
  const extractDir = join(tempDir, "src");
  mkdirSync(downloadDir, { recursive: true });
  mkdirSync(extractDir, { recursive: true });

  const spec = requestedVersion ? `${packageName}==${requestedVersion}` : packageName;
  emit({ type: "stage:start", stage: "discovery", message: `Downloading PyPI package ${spec}...` });

  try {
    execFileSync(
      "python3",
      ["-m", "pip", "download", "--no-deps", "--no-binary", ":all:", spec, "-d", downloadDir],
      {
        cwd: tempDir,
        timeout: 180_000,
        stdio: "pipe",
      },
    );
  } catch (firstErr) {
    try {
      execFileSync(
        "python3",
        ["-m", "pip", "download", "--no-deps", spec, "-d", downloadDir],
        {
          cwd: tempDir,
          timeout: 180_000,
          stdio: "pipe",
        },
      );
    } catch (secondErr) {
      rmSync(tempDir, { recursive: true, force: true });
      const msg = secondErr instanceof Error ? secondErr.message : String(secondErr);
      throw new Error(`Failed to download ${spec} from PyPI: ${msg}`);
    }
  }

  const archives = readdirSync(downloadDir)
    .filter((name) => /\.(?:tar\.gz|zip|whl)$/i.test(name))
    .map((name) => join(downloadDir, name));
  if (archives.length === 0) {
    rmSync(tempDir, { recursive: true, force: true });
    throw new Error(`PyPI download for ${spec} produced no extractable archive.`);
  }

  const archivePath = archives[0]!;
  extractSingleArchive(archivePath, extractDir);
  const scopePath = pickPythonScopePath(extractDir);

  let installedVersion = requestedVersion;
  const pyprojectPath = join(scopePath, "pyproject.toml");
  const setupPyPath = join(scopePath, "setup.py");
  if (!installedVersion && existsSync(pyprojectPath)) {
    const content = readFileSync(pyprojectPath, "utf8");
    const match = content.match(/^\s*version\s*=\s*["']([^"']+)["']/m);
    installedVersion = match?.[1];
  }
  if (!installedVersion && existsSync(setupPyPath)) {
    const content = readFileSync(setupPyPath, "utf8");
    const match = content.match(/version\s*=\s*["']([^"']+)["']/m);
    installedVersion = match?.[1];
  }
  if (!installedVersion) {
    installedVersion = readPythonVersionFromMetadata(scopePath);
  }
  if (!installedVersion) {
    installedVersion = readPythonVersionFromArchiveName(packageName, archivePath);
  }
  installedVersion = installedVersion ?? "unknown";

  writeFileSync(join(tempDir, "requirements.txt"), `${packageName}==${installedVersion}\n`, "utf8");
  emit({ type: "stage:end", stage: "discovery", message: `Prepared ${packageName}==${installedVersion} from PyPI` });

  return {
    ecosystem: "pypi",
    name: packageName,
    version: installedVersion,
    path: scopePath,
    tempDir,
  };
}

function resolveCargoVersion(packageName: string, requestedVersion: string | undefined): string {
  if (requestedVersion) return requestedVersion;

  const raw = execFileSync("curl", ["-fsSL", `https://crates.io/api/v1/crates/${packageName}`], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 60_000,
  });
  const parsed = JSON.parse(raw) as {
    crate?: { max_stable_version?: string; max_version?: string; newest_version?: string };
  };
  return (
    parsed.crate?.max_stable_version ??
    parsed.crate?.max_version ??
    parsed.crate?.newest_version ??
    "latest"
  );
}

function installCargoPackage(
  packageName: string,
  requestedVersion: string | undefined,
  emit: ScanListener,
): InstalledPackage {
  const tempDir = join(tmpdir(), `pwnkit-audit-${randomUUID().slice(0, 8)}`);
  const downloadDir = join(tempDir, "downloads");
  const extractDir = join(tempDir, "src");
  mkdirSync(downloadDir, { recursive: true });
  mkdirSync(extractDir, { recursive: true });

  const version = resolveCargoVersion(packageName, requestedVersion);
  emit({ type: "stage:start", stage: "discovery", message: `Downloading crates.io crate ${packageName}@${version}...` });

  try {
    execFileSync(
      "curl",
      ["-fsSL", `https://crates.io/api/v1/crates/${packageName}/${version}/download`, "-o", join(downloadDir, `${packageName}-${version}.crate`)],
      {
        cwd: tempDir,
        timeout: 120_000,
        stdio: "pipe",
      },
    );
  } catch (err) {
    rmSync(tempDir, { recursive: true, force: true });
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to download ${packageName}@${version} from crates.io: ${msg}`);
  }

  const archivePath = join(downloadDir, `${packageName}-${version}.crate`);
  extractSingleArchive(archivePath, extractDir);
  const scopePath = pickPythonScopePath(extractDir);

  const cargoTomlPath = join(scopePath, "Cargo.toml");
  let resolvedVersion = version;
  if (existsSync(cargoTomlPath)) {
    const content = readFileSync(cargoTomlPath, "utf8");
    const match = content.match(/^\s*version\s*=\s*["']([^"']+)["']/m);
    resolvedVersion = match?.[1] ?? version;
  }

  writeFileSync(
    join(tempDir, "Cargo.toml"),
    `[package]\nname = "pwnkit-cargo-audit"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\n${packageName} = "${resolvedVersion}"\n`,
    "utf8",
  );
  mkdirSync(join(tempDir, "src"), { recursive: true });
  writeFileSync(join(tempDir, "src", "main.rs"), "fn main() {}\n", "utf8");
  try {
    execFileSync("cargo", ["generate-lockfile"], {
      cwd: tempDir,
      timeout: 180_000,
      stdio: "pipe",
    });
  } catch {
    // Best-effort: advisory lookup can still degrade to OSV only.
  }

  emit({ type: "stage:end", stage: "discovery", message: `Prepared ${packageName}@${resolvedVersion} from crates.io` });
  return {
    ecosystem: "cargo",
    name: packageName,
    version: resolvedVersion,
    path: scopePath,
    tempDir,
  };
}

export function installPackageForEcosystem(
  ecosystem: PackageEcosystem,
  rawPackageName: string,
  requestedVersion: string | undefined,
  emit: ScanListener,
): InstalledPackage {
  const { packageName, version } = splitPackageSpec(rawPackageName, requestedVersion);
  if (ecosystem === "pypi") return installPypiPackage(packageName, version, emit);
  if (ecosystem === "cargo") return installCargoPackage(packageName, version, emit);
  return installNpmPackage(packageName, version, emit);
}

export function runDependencyAuditForEcosystem(
  ecosystem: PackageEcosystem,
  projectDir: string,
  emit: ScanListener,
): NpmAuditFinding[] {
  if (ecosystem === "cargo") {
    emit({ type: "stage:start", stage: "discovery", message: "Running cargo audit..." });
    const commands: Array<{ cmd: string; args: string[] }> = [
      { cmd: "cargo", args: ["audit", "--json", "--stale", "--no-fetch", "-f", "Cargo.lock"] },
      { cmd: "cargo-audit", args: ["--json", "--stale", "--no-fetch", "-f", "Cargo.lock"] },
    ];
    let rawOutput = "";
    let sawExecutable = false;
    for (const command of commands) {
      try {
        rawOutput = execFileSync(command.cmd, command.args, {
          cwd: projectDir,
          timeout: 60_000,
          encoding: "utf8",
          stdio: ["ignore", "pipe", "ignore"],
        });
        sawExecutable = true;
        break;
      } catch (err: any) {
        if (err && err.code === "ENOENT") {
          continue;
        }
        sawExecutable = true;
        rawOutput = (err && typeof err.stdout === "string" ? err.stdout : "") || "";
        if (rawOutput) break;
      }
    }
    if (!sawExecutable && !rawOutput) {
      emit({ type: "stage:end", stage: "discovery", message: "cargo audit unavailable" });
      return [];
    }
    if (!rawOutput) {
      emit({ type: "stage:end", stage: "discovery", message: "cargo audit unavailable" });
      return [];
    }
    const findings = parseCargoAuditOutput(rawOutput);
    emit({ type: "stage:end", stage: "discovery", message: `cargo audit: ${findings.length} advisories` });
    return findings;
  }

  if (ecosystem === "pypi") {
    emit({ type: "stage:start", stage: "discovery", message: "Running pip-audit..." });
    const commands: Array<{ cmd: string; args: string[] }> = [
      { cmd: "pip-audit", args: ["--requirement", "requirements.txt", "--format", "json"] },
      { cmd: "python3", args: ["-m", "pip_audit", "--requirement", "requirements.txt", "--format", "json"] },
      { cmd: "python3", args: ["-m", "pip-audit", "--requirement", "requirements.txt", "--format", "json"] },
    ];
    let rawOutput = "";
    let sawExecutable = false;
    for (const command of commands) {
      try {
        rawOutput = execFileSync(command.cmd, command.args, {
          cwd: projectDir,
          timeout: 60_000,
          encoding: "utf8",
          stdio: ["ignore", "pipe", "ignore"],
        });
        sawExecutable = true;
        break;
      } catch (err: any) {
        if (err && err.code === "ENOENT") {
          continue;
        }
        sawExecutable = true;
        rawOutput = (err && typeof err.stdout === "string" ? err.stdout : "") || "";
        if (rawOutput) break;
      }
    }
    if (!sawExecutable && !rawOutput) {
      emit({ type: "stage:end", stage: "discovery", message: "pip-audit unavailable" });
      return [];
    }
    if (!rawOutput) {
      emit({ type: "stage:end", stage: "discovery", message: "pip-audit unavailable" });
      return [];
    }
    const findings = parsePipAuditOutput(rawOutput);
    emit({ type: "stage:end", stage: "discovery", message: `pip-audit: ${findings.length} advisories` });
    return findings;
  }

  emit({ type: "stage:start", stage: "discovery", message: "Running npm audit..." });
  let rawOutput = "";
  try {
    rawOutput = execSync("npm audit --json", {
      cwd: projectDir,
      timeout: 120_000,
      stdio: "pipe",
    }).toString("utf-8");
  } catch (err) {
    const stdout =
      err && typeof err === "object" && "stdout" in err
        ? (err.stdout as Buffer | string | undefined)
        : undefined;
    const stderr =
      err && typeof err === "object" && "stderr" in err
        ? (err.stderr as Buffer | string | undefined)
        : undefined;
    rawOutput = bufferToString(stdout) || bufferToString(stderr) || "";
  }
  const findings = parseNpmAuditOutput(rawOutput);
  emit({ type: "stage:end", stage: "discovery", message: `npm audit: ${findings.length} advisories` });
  return findings;
}
