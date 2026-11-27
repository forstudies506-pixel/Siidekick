/**
 * Shared contract for the engine, API and web dashboard.
 * Change this file only through the board (GitHub issue), because every workstream imports it.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** ROADMAP §13: auto = new files/config after approval, template = draft owner completes, report = findings only. */
export type FixMode = "auto" | "template" | "report";

/** ROADMAP §13 groups A–G. */
export type CheckGroup =
  | "A-delivery"
  | "B-monitoring"
  | "C-security"
  | "D-domain"
  | "E-states"
  | "F-ai"
  | "G-enterprise";

/** A repo held in memory. Uploaded code is never executed by the engine. */
export interface RepoFile {
  path: string; // POSIX, relative to repo root
  content: string;
}

export interface RepoSnapshot {
  name: string;
  files: RepoFile[];
}

export interface Finding {
  checkId: string;
  title: string;
  severity: Severity;
  file?: string;
  line?: number;
  /** Must never contain a full secret. Use redact() from util. */
  evidence?: string;
  /** Plain-language reason this matters. */
  explanation: string;
  /** Copy-ready fix for report-only findings, e.g. the header line for the owner's host. */
  remedy?: string;
}

/** additive: only adds lines/files. minimal-edit: may change a few declared lines (ROADMAP §9). */
export type PatchClass = "additive" | "minimal-edit";

export type FileEdit =
  | { kind: "create"; path: string; content: string }
  | { kind: "modify"; path: string; before: string; after: string };

export interface Patch {
  id: string;
  checkId: string;
  title: string;
  class: PatchClass;
  /** Why this change, what risk it reduces. Shown to the owner before approval. */
  reason: string;
  edits: FileEdit[];
  /**
   * minimal-edit only: exact (trimmed) text of every user line this patch may remove.
   * The diff guard rejects any removed line not listed here.
   */
  allowedRemovals?: string[];
  /** One-line command that reverts the patch, e.g. `git revert <sha>`. Filled by the applier. */
  revert?: string;
}

export interface CheckContext {
  repo: RepoSnapshot;
  /** Injected so detectors stay testable offline. */
  fetch?: typeof fetch;
}

export interface Check {
  id: string; // kebab-case, stable, e.g. "secrets-in-repo"
  group: CheckGroup;
  title: string;
  severity: Severity;
  mode: FixMode;
  /**
   * Optional. Returns a plain reason when the check does not apply to this repo (no server to
   * harden, for example), else null. A skipped check runs no detector and counts toward no score.
   */
  skip?(ctx: CheckContext): string | null;
  detect(ctx: CheckContext): Finding[] | Promise<Finding[]>;
  /** null when nothing to fix or mode is "report". Fixers are deterministic templates, not model output. */
  fix?(ctx: CheckContext, findings: Finding[]): Patch | null | Promise<Patch | null>;
}

export interface GuardViolation {
  path: string;
  reason:
    | "removed-line-not-allowed"
    | "removal-in-additive-patch"
    | "patch-too-large"
    | "overwrites-existing-file"
    | "modify-missing-file"
    | "before-mismatch";
  line?: string;
}

export interface GuardResult {
  ok: boolean;
  added: number;
  removed: number;
  violations: GuardViolation[];
}

export interface CheckResult {
  checkId: string;
  title: string;
  group: CheckGroup;
  severity: Severity;
  mode: FixMode;
  passed: boolean;
  findings: Finding[];
  error?: string;
  /** Set when the check does not apply to this repo: why. Such a result has passed true and no findings. */
  skipped?: string;
}

/**
 * 2.pdf trust rule: "verified" only when the re-scan is clean AND build/tests passed;
 * the label must say where the tests ran.
 */
export type VerifyStatus = "unverified" | "rescan-clean" | "verified";

export interface ScanReport {
  repo: string;
  startedAt: string;
  score: number; // 0–100
  /** Applicable checks that passed; skipped checks are in neither passed nor total. */
  passed: number;
  total: number;
  /** Checks that did not apply to this repo. */
  skipped?: number;
  /** Open findings by severity, across every applicable check. */
  open?: Record<Severity, number>;
  /**
   * The worst open severity, in words. The score counts passing checks; this says how bad what is
   * left is, so "59/100" never hides an open critical.
   */
  risk?: "critical" | "high" | "medium" | "low" | "clear";
  results: CheckResult[];
}
