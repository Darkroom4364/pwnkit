/**
 * PTY Session Manager — manages interactive terminal sessions for exploits
 * requiring interactivity (reverse shells, database clients, SSH).
 *
 * Uses child_process.spawn with stdio: 'pipe' as a zero-dependency approach.
 * node-pty can be added later for full PTY support (line discipline, etc.).
 */

import { spawn, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";

export interface PtySession {
  id: string;
  name: string;
  process: ChildProcess;
  outputBuffer: string;
  cwd: string;
  createdAt: number;
  lastActivityAt: number;
  alive: boolean;
}

export class PtySessionManager {
  private sessions = new Map<string, PtySession>();

  /** Maximum number of concurrent alive sessions. */
  static readonly MAX_CONCURRENT_SESSIONS = 10;

  /** Idle timeout in milliseconds (10 minutes). Sessions with no I/O are reaped. */
  static readonly IDLE_TIMEOUT_MS = 10 * 60 * 1000;

  /**
   * Create a new interactive session backed by a shell process.
   */
  createSession(name: string, opts?: { cwd?: string; env?: Record<string, string> }): PtySession {
    // Prevent duplicate session names
    for (const s of this.sessions.values()) {
      if (s.name === name && s.alive) {
        throw new Error(`Session "${name}" already exists and is alive. Close it first or use a different name.`);
      }
    }

    // Enforce maximum concurrent session limit
    const aliveCount = Array.from(this.sessions.values()).filter((s) => s.alive).length;
    if (aliveCount >= PtySessionManager.MAX_CONCURRENT_SESSIONS) {
      // Reap idle sessions first before rejecting
      this.reapIdleSessions();
      const aliveAfterReap = Array.from(this.sessions.values()).filter((s) => s.alive).length;
      if (aliveAfterReap >= PtySessionManager.MAX_CONCURRENT_SESSIONS) {
        throw new Error(
          `Maximum concurrent session limit (${PtySessionManager.MAX_CONCURRENT_SESSIONS}) reached. Close existing sessions first.`,
        );
      }
    }

    const id = randomUUID().slice(0, 8);
    const cwd = opts?.cwd ?? process.cwd();

    const proc = spawn("/bin/bash", ["--norc", "--noprofile", "-i"], {
      cwd,
      env: { ...process.env, ...opts?.env, TERM: "dumb" },
      stdio: ["pipe", "pipe", "pipe"],
    });

    const session: PtySession = {
      id,
      name,
      process: proc,
      outputBuffer: "",
      cwd,
      createdAt: Date.now(),
      lastActivityAt: Date.now(),
      alive: true,
    };

    // Accumulate stdout
    proc.stdout?.on("data", (chunk: Buffer) => {
      session.outputBuffer += chunk.toString("utf-8");
      session.lastActivityAt = Date.now();
      // Cap buffer at 100KB to prevent unbounded growth
      if (session.outputBuffer.length > 100_000) {
        session.outputBuffer = session.outputBuffer.slice(-50_000);
      }
    });

    // Accumulate stderr into same buffer
    proc.stderr?.on("data", (chunk: Buffer) => {
      session.outputBuffer += chunk.toString("utf-8");
      session.lastActivityAt = Date.now();
      if (session.outputBuffer.length > 100_000) {
        session.outputBuffer = session.outputBuffer.slice(-50_000);
      }
    });

    proc.on("exit", (_code) => {
      session.alive = false;
    });

    proc.on("error", (_err) => {
      session.alive = false;
    });

    this.sessions.set(id, session);
    return session;
  }

  /**
   * Send input to a session's stdin. Appends a newline if not present.
   */
  send(sessionId: string, input: string): void {
    const session = this.getSession(sessionId);
    if (!session.alive) {
      throw new Error(`Session "${session.name}" (${sessionId}) is no longer alive.`);
    }
    if (!session.process.stdin?.writable) {
      throw new Error(`Session "${session.name}" (${sessionId}) stdin is not writable.`);
    }
    const data = input.endsWith("\n") ? input : input + "\n";
    session.process.stdin.write(data);
    session.lastActivityAt = Date.now();
  }

  /**
   * Read available output from a session. Waits up to `timeout` ms for new output.
   * Returns whatever is in the buffer and clears it.
   */
  async read(sessionId: string, timeout = 5000): Promise<string> {
    const session = this.getSession(sessionId);

    // If buffer already has content, return it immediately
    if (session.outputBuffer.length > 0) {
      const output = session.outputBuffer;
      session.outputBuffer = "";
      return output;
    }

    // Wait for output up to timeout
    return new Promise<string>((resolve) => {
      const start = Date.now();

      const check = () => {
        if (session.outputBuffer.length > 0 || !session.alive) {
          const output = session.outputBuffer;
          session.outputBuffer = "";
          resolve(output);
          return;
        }
        if (Date.now() - start >= timeout) {
          resolve(""); // Timeout with no output
          return;
        }
        setTimeout(check, 100);
      };

      check();
    });
  }

  /**
   * Close/terminate a session.
   */
  close(sessionId: string): void {
    const session = this.getSession(sessionId);
    if (session.alive) {
      session.process.kill("SIGTERM");
      // Force kill after 2s if still alive
      setTimeout(() => {
        if (session.alive) {
          session.process.kill("SIGKILL");
        }
      }, 2000);
    }
    session.alive = false;
    this.sessions.delete(sessionId);
  }

  /**
   * List all sessions (active and dead).
   */
  listSessions(): Array<{ id: string; name: string; alive: boolean; cwd: string; createdAt: number }> {
    return Array.from(this.sessions.values()).map((s) => ({
      id: s.id,
      name: s.name,
      alive: s.alive,
      cwd: s.cwd,
      createdAt: s.createdAt,
    }));
  }

  /**
   * Clean up all sessions. Call when the agent loop ends.
   */
  cleanup(): void {
    for (const [id] of this.sessions) {
      try {
        this.close(id);
      } catch {
        // Best-effort
      }
    }
    this.sessions.clear();
  }

  /**
   * Reap sessions that have been idle longer than IDLE_TIMEOUT_MS.
   */
  reapIdleSessions(): void {
    const now = Date.now();
    for (const [id, session] of this.sessions) {
      if (session.alive && now - session.lastActivityAt > PtySessionManager.IDLE_TIMEOUT_MS) {
        try {
          this.close(id);
        } catch {
          // Best-effort
        }
      }
    }
  }

  /**
   * Find a session by name (returns the first alive match, or any match).
   */
  findByName(name: string): PtySession | undefined {
    for (const s of this.sessions.values()) {
      if (s.name === name && s.alive) return s;
    }
    // Fall back to dead sessions
    for (const s of this.sessions.values()) {
      if (s.name === name) return s;
    }
    return undefined;
  }

  private getSession(sessionId: string): PtySession {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Session "${sessionId}" not found.`);
    }
    return session;
  }
}
