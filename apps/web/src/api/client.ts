import type { DiffLine } from "../../../../packages/engine/src/diffGuard";
import type { CheckGroup, FileEdit, GuardResult, Patch, RepoFile, ScanReport, Severity } from "../../../../packages/engine/src/types";
import { createMockPatches, createMockScan, mockDownload } from "./mock";

export type { DiffLine };

export interface FileDiff {
  path: string;
  lines: DiffLine[];
}

export interface PatchEntry {
  patch: Patch;
  guard: GuardResult;
  diff: FileDiff[];
}

/** Where a website scan looked, after redirects. */
export interface SiteInfo {
  url: string;
  finalUrl: string;
  fetchedAt: string;
}

export interface ScanResponse {
  id: string;
  report: ScanReport;
  mock: boolean;
  /** Text files of a big GitHub repo left out past the size caps. */
  omitted?: number;
  /** Set for a live website scan: report only, nothing to patch. */
  kind?: "site";
  site?: SiteInfo;
}

export interface PatchResponse {
  patches: PatchEntry[];
  scoreBefore: number;
  scoreAfter: number;
  status: "rescan-clean" | "partial";
  mock: boolean;
}

export interface DownloadResponse {
  files: { path: string; content: string }[];
}

class ApiUnavailable extends Error {}

// Sample data only when the build asks for it (VITE_MOCK=1). A real build never falls back to it:
// an offline server is shown as an error, so a result on screen is always a real scan.
let mockSession = import.meta.env.VITE_MOCK === "1";
const OFFLINE = "The scan server is not running. Start it with: npm run dev -w apps/api";
const mockApproved = new Set<string>();

export function isMockSession() {
  return mockSession;
}

/** Turns a dead server into one readable message instead of "network" or a status code. */
async function live<T>(pending: Promise<T>): Promise<T> {
  try {
    return await pending;
  } catch (e) {
    if (e instanceof ApiUnavailable) throw new Error(OFFLINE);
    throw e;
  }
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null;

async function request<T>(path: string, init: RequestInit, valid: (v: unknown) => boolean): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, init);
  } catch {
    throw new ApiUnavailable("network");
  }
  if (res.status >= 500) throw new ApiUnavailable(String(res.status));
  let body: unknown;
  try {
    body = await res.json();
  } catch {
    throw new ApiUnavailable("not json");
  }
  if (!res.ok) {
    const msg = isObj(body) && typeof body.error === "string" ? body.error : `request failed (${res.status})`;
    throw new Error(msg);
  }
  if (!valid(body)) throw new Error("The server sent a response this page does not understand.");
  return body as T;
}

const validScan = (v: unknown) => isObj(v) && typeof v.id === "string" && isObj(v.report) && Array.isArray(v.report.results);
const validPatches = (v: unknown) => isObj(v) && Array.isArray(v.patches) && typeof v.scoreBefore === "number" && typeof v.scoreAfter === "number";
const validApprove = (v: unknown) => isObj(v) && Array.isArray(v.approved);
const validDownload = (v: unknown) => isObj(v) && Array.isArray(v.files);

async function createScan(path: string, init: RequestInit, name: string): Promise<ScanResponse> {
  mockApproved.clear();
  if (mockSession) return createMockScan(name);
  try {
    const r = await request<Omit<ScanResponse, "mock">>(path, init, validScan);
    return { ...r, mock: false };
  } catch (e) {
    if (e instanceof ApiUnavailable) throw new Error(OFFLINE);
    throw e;
  }
}

export function createDemoScan(): Promise<ScanResponse> {
  return createScan("/api/scans/demo", { method: "POST" }, "campuskart");
}

export function uploadScan(name: string, files: RepoFile[]): Promise<ScanResponse> {
  return createScan(
    "/api/scans",
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name, files }) },
    name,
  );
}

// GitHub and website scans only work on the real API: sample data has no copy of someone else's code or site.
async function liveScan(path: string, url: string): Promise<ScanResponse> {
  mockApproved.clear();
  try {
    const r = await request<Omit<ScanResponse, "mock">>(
      path,
      { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url }) },
      validScan,
    );
    mockSession = false;
    return { ...r, mock: false };
  } catch (e) {
    if (e instanceof ApiUnavailable) throw new Error(OFFLINE);
    throw e;
  }
}

export const githubScan = (url: string) => liveScan("/api/scans/github", url);

/** Passive scan of a live website: reads its headers, cookies and HTML. */
export const siteScan = (url: string) => liveScan("/api/sites", url);

/** github.com/owner/repo goes to the repo scanner; any other address is scanned as a website. */
export function isGithubRepo(input: string): boolean {
  try {
    const u = new URL(/^[a-z]+:\/\//i.test(input.trim()) ? input.trim() : `https://${input.trim()}`);
    return /^(www\.)?github\.com$/i.test(u.hostname) && u.pathname.split("/").filter(Boolean).length >= 2;
  } catch {
    return false;
  }
}

/** One check the engine runs, as listed by GET /api/checks. */
export interface CheckInfo {
  id: string;
  title: string;
  group: CheckGroup;
  severity: Severity;
}

const validCheckList = (v: unknown) => isObj(v) && Array.isArray(v.repo) && Array.isArray(v.site);

export function getChecks(): Promise<{ repo: CheckInfo[]; site: CheckInfo[] }> {
  return live(request("/api/checks", { method: "GET" }, validCheckList));
}

export interface CheckResponse {
  guard: GuardResult;
  diff: FileDiff[];
}

const validCheck = (v: unknown) => isObj(v) && isObj(v.guard) && Array.isArray(v.diff);

/** Sends an edited copy of a patch to the server's diff guard. Nothing is stored or applied. */
export async function checkPatch(id: string, patchId: string, edits: FileEdit[]): Promise<CheckResponse> {
  try {
    return await request<CheckResponse>(
      `/api/scans/${encodeURIComponent(id)}/patches/${encodeURIComponent(patchId)}/check`,
      { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ edits }) },
      validCheck,
    );
  } catch (e) {
    if (e instanceof ApiUnavailable) throw new Error("The scan server is offline, so the guard cannot be asked.");
    throw e;
  }
}

export async function generatePatches(id: string, name: string): Promise<PatchResponse> {
  if (mockSession) return createMockPatches(name);
  const r = await live(request<Omit<PatchResponse, "mock">>(`/api/scans/${encodeURIComponent(id)}/patches`, { method: "POST" }, validPatches));
  return { ...r, mock: false };
}

/** Rescan of the repo with only the approved fixes applied. */
export interface ApprovedSummary {
  score: number;
  passed: number;
  total: number;
  /** Check ids still failing once the approved fixes are in. */
  failing: string[];
}

export interface ApproveResponse extends Partial<ApprovedSummary> {
  approved: string[];
}

export async function approve(id: string, patchId: string): Promise<ApproveResponse> {
  if (mockSession) {
    mockApproved.add(patchId);
    return { approved: [...mockApproved] };
  }
  return live(
    request<ApproveResponse>(
      `/api/scans/${encodeURIComponent(id)}/patches/${encodeURIComponent(patchId)}/approve`,
      { method: "POST" },
      validApprove,
    ),
  );
}

/** A scan as the server stored it, for reopening a link or a recent scan. */
export interface StoredScan {
  id: string;
  report: ScanReport;
  patches?: (PatchEntry & { patchId: string; approved: boolean })[];
  after?: ScanReport;
  omitted?: number;
  demo?: boolean;
  approvedSummary?: ApprovedSummary;
  kind?: "site";
  site?: SiteInfo;
}

export async function getScan(id: string): Promise<StoredScan> {
  try {
    const r = await request<StoredScan>(`/api/scans/${encodeURIComponent(id)}`, { method: "GET" }, validScan);
    mockSession = false;
    return r;
  } catch (e) {
    if (e instanceof ApiUnavailable) throw new Error(OFFLINE);
    throw e;
  }
}

// Mirrors the report in packages/engine/src/replay.ts. Declared here because that module imports node-only APIs.
export type ReplayVerdict = "blocked" | "still-open" | "not-reproduced" | "inconclusive";
export interface Probe {
  exploited: boolean;
  detail: string;
}
export interface AttackReceipt {
  id: string;
  checkId: string;
  title: string;
  request: string;
  kind: "live" | "static";
  before: Probe;
  after: Probe;
  control?: { label: string; ok: boolean };
  verdict: ReplayVerdict;
}
export interface AttackPath {
  id: string;
  title: string;
  impact: "critical" | "high";
  steps: { attackId: string; text: string; before: boolean; after: boolean }[];
  openBefore: boolean;
  openAfter: boolean;
  cutBy: string[];
}
export interface ReplayReport {
  available: boolean;
  reason?: string;
  attacks: AttackReceipt[];
  paths: AttackPath[];
  tests?: { ran: boolean; passed: number; failed: number };
  ms: number;
}

const validReplay = (v: unknown) => isObj(v) && typeof v.available === "boolean" && Array.isArray(v.attacks) && Array.isArray(v.paths);

/** Attacks the demo shop as scanned and as patched with the approved fixes. The server refuses any other repo. */
export async function proveFix(id: string): Promise<ReplayReport> {
  if (mockSession) throw new Error("Attack replay needs the scan server. Demo data cannot be attacked.");
  try {
    return await request<ReplayReport>(`/api/scans/${encodeURIComponent(id)}/prove`, { method: "POST" }, validReplay);
  } catch (e) {
    if (e instanceof ApiUnavailable) throw new Error("The scan server is offline, so the attacks cannot be replayed.");
    throw e;
  }
}

export async function download(id: string): Promise<DownloadResponse> {
  if (mockSession) return mockDownload([...mockApproved]);
  return live(request<DownloadResponse>(`/api/scans/${encodeURIComponent(id)}/download`, { method: "GET" }, validDownload));
}
