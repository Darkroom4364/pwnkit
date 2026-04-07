/**
 * node-sqlite3-wasm → better-sqlite3 API shim.
 *
 * Exposes `createShimmedDatabase(path)` and `createDrizzleFromShim(...)`,
 * both of which return objects that present the better-sqlite3 surface area
 * expected by drizzle-orm's `BetterSQLiteSession`. This lets pwnkit use a
 * pure-WASM SQLite implementation (no native bindings, no NODE_MODULE_VERSION
 * drift) while keeping the existing drizzle query-builder code unchanged.
 *
 * Background: better-sqlite3 ships native `.node` files per Node ABI and
 * occasionally the `prebuild-install` dependency chain picks the wrong one,
 * producing the infamous `NODE_MODULE_VERSION X requires NODE_MODULE_VERSION Y`
 * crash. WASM sidesteps this entirely — one binary runs on every Node version,
 * Bun, Deno, Electron, whatever.
 */

// node-sqlite3-wasm ships as CommonJS; import via default interop so the
// class constructors survive ESM transpilation.
import sqliteWasm from "node-sqlite3-wasm";
type WasmDatabase = InstanceType<typeof sqliteWasm.Database>;
type WasmStatement = InstanceType<typeof sqliteWasm.Statement>;
const { Database: WasmDatabaseCtor } = sqliteWasm;
// We import BetterSQLiteSession from the deep `/session` subpath to avoid
// pulling in `drizzle-orm/better-sqlite3/driver.js`, which `import`s
// `better-sqlite3` at module load and would defeat the whole point.
import { BetterSQLiteSession } from "drizzle-orm/better-sqlite3/session";
import { BaseSQLiteDatabase } from "drizzle-orm/sqlite-core/db";
import { SQLiteSyncDialect } from "drizzle-orm/sqlite-core/dialect";
import {
  createTableRelationsHelpers,
  extractTablesRelationalConfig,
  type RelationalSchemaConfig,
  type TablesRelationalConfig,
} from "drizzle-orm/relations";

type BindValue = number | bigint | string | Uint8Array | null | boolean;

interface RunResult {
  changes: number;
  lastInsertRowid: number | bigint;
}

/**
 * Normalize the varargs drizzle-orm (and better-sqlite3 users) pass to
 * `stmt.run(...args)` into the single-argument form node-sqlite3-wasm expects.
 *
 * Rules:
 *  - zero args           → undefined (no binding)
 *  - N positional args   → array of args
 *  - single object arg   → assume named binding; prepend `@` to each key so
 *                          node-sqlite3-wasm matches the existing `@name`
 *                          placeholders used in our raw-SQL sites
 */
function normalizeBindArgs(args: unknown[]): unknown {
  if (args.length === 0) return undefined;
  if (args.length === 1) {
    const a = args[0];
    if (
      a !== null &&
      typeof a === "object" &&
      !Array.isArray(a) &&
      !(a instanceof Uint8Array)
    ) {
      // Named binding: keys like { id, scope } → { "@id": ..., "@scope": ... }
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(a as Record<string, unknown>)) {
        // If the caller already included a sigil, respect it; otherwise add @.
        out[/^[:@$]/.test(k) ? k : `@${k}`] = v;
      }
      return out;
    }
    // Single positional value (string/number/etc) — wrap in array so the
    // wasm driver treats it as positional rather than named.
    return [a as BindValue];
  }
  return args as BindValue[];
}

class StatementShim {
  constructor(private readonly stmt: WasmStatement, private readonly rawMode = false) {}

  run(...args: unknown[]): RunResult {
    const bind = normalizeBindArgs(args);
    return this.stmt.run(bind as any) as unknown as RunResult;
  }

  get(...args: unknown[]): unknown {
    const bind = normalizeBindArgs(args);
    const row = this.stmt.get(bind as any);
    if (row == null) return undefined;
    if (!this.rawMode) return row;
    // drizzle's `raw().get()` expects row values as an ordered array.
    // node-sqlite3-wasm returns a plain object whose key-insertion order
    // matches the result column order, so Object.values() preserves it.
    return Object.values(row);
  }

  all(...args: unknown[]): unknown[] {
    const bind = normalizeBindArgs(args);
    const rows = this.stmt.all(bind as any);
    if (!this.rawMode) return rows;
    return rows.map((r) => Object.values(r));
  }

  /** better-sqlite3 compat: return a statement that yields rows as arrays. */
  raw(): StatementShim {
    return new StatementShim(this.stmt, true);
  }

  // Stubs for methods drizzle never calls but better-sqlite3 exposes.
  // Keeps TypeScript structural typing happy if something reaches for them.
  pluck(): this {
    return this;
  }
  expand(): this {
    return this;
  }
  bind(): this {
    return this;
  }
}

/**
 * better-sqlite3 Database look-alike. Wraps node-sqlite3-wasm and exposes the
 * subset of the better-sqlite3 API that pwnkit's database.ts and drizzle's
 * `BetterSQLiteSession` actually call.
 */
export class ShimmedDatabase {
  constructor(private readonly wasm: WasmDatabase) {}

  prepare(sql: string): StatementShim {
    return new StatementShim(this.wasm.prepare(sql));
  }

  exec(sql: string): this {
    this.wasm.exec(sql);
    return this;
  }

  /**
   * better-sqlite3 uses `.pragma()` both as a getter and a setter. Our code
   * only uses it as a setter ("journal_mode = WAL", "foreign_keys = ON"), so
   * we just `exec()` the pragma and swallow errors — some PRAGMAs (notably
   * WAL journal mode) are not supported by node-sqlite3-wasm's VFS and error
   * here, but losing them is acceptable for pwnkit's single-process workload.
   */
  pragma(query: string, _opts?: { simple?: boolean }): unknown {
    try {
      this.wasm.exec(`PRAGMA ${query}`);
    } catch {
      // Silently ignore PRAGMAs the WASM VFS doesn't support (e.g. WAL).
    }
    return undefined;
  }

  /**
   * better-sqlite3's `db.transaction(fn)` returns a callable object with
   * `.deferred`, `.immediate`, `.exclusive`, and `.default` methods, each
   * running `fn` inside a BEGIN/COMMIT of the corresponding isolation level.
   * All three variants are functionally equivalent for pwnkit's single-writer
   * workload, so we wire them to the same underlying implementation.
   */
  transaction<Args extends unknown[], R>(fn: (...args: Args) => R) {
    const wasm = this.wasm;
    const runInTx = (...args: Args): R => {
      wasm.exec("BEGIN");
      try {
        const result = fn(...args);
        wasm.exec("COMMIT");
        return result;
      } catch (err) {
        try {
          wasm.exec("ROLLBACK");
        } catch {
          // If the rollback itself fails, surface the original error.
        }
        throw err;
      }
    };
    return Object.assign(runInTx, {
      default: runInTx,
      deferred: runInTx,
      immediate: runInTx,
      exclusive: runInTx,
    });
  }

  close(): void {
    this.wasm.close();
  }

  get inTransaction(): boolean {
    return this.wasm.inTransaction;
  }

  get open(): boolean {
    return this.wasm.isOpen;
  }

  /** Internal escape hatch for code that needs the raw wasm handle. */
  get __wasm(): WasmDatabase {
    return this.wasm;
  }
}

export function createShimmedDatabase(path: string): ShimmedDatabase {
  const wasm = new WasmDatabaseCtor(path);
  return new ShimmedDatabase(wasm);
}

/**
 * Build a drizzle BaseSQLiteDatabase bound to our shimmed client. Mirrors
 * what `drizzle-orm/better-sqlite3/driver.js::construct()` does, minus the
 * top-of-file `import Client from "better-sqlite3"` that would load the
 * native binding.
 */
export function createDrizzleFromShim<
  TSchema extends Record<string, unknown>,
>(
  client: ShimmedDatabase,
  config: { schema?: TSchema } = {},
): BaseSQLiteDatabase<"sync", RunResult, TSchema> {
  const dialect = new SQLiteSyncDialect({});
  let schema: RelationalSchemaConfig<TablesRelationalConfig> | undefined;
  if (config.schema) {
    const tablesConfig = extractTablesRelationalConfig(
      config.schema,
      createTableRelationsHelpers,
    );
    schema = {
      fullSchema: config.schema,
      schema: tablesConfig.tables,
      tableNamesMap: tablesConfig.tableNamesMap,
    };
  }
  // `client` is structurally compatible with better-sqlite3's Database for
  // the methods BetterSQLiteSession actually calls (prepare, transaction).
  const session = new BetterSQLiteSession(
    client as any,
    dialect,
    schema as any,
    {},
  );
  const db = new BaseSQLiteDatabase("sync", dialect, session, schema as any);
  (db as any).$client = client;
  return db as BaseSQLiteDatabase<"sync", RunResult, TSchema>;
}
