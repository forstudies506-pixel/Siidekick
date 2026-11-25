import type { DiffLine } from "../../../../packages/engine/src/diffGuard";
import type { FileEdit, GuardResult, Patch, RepoFile, ScanReport } from "../../../../packages/engine/src/types";
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

export interface ScanResponse {
  id: string;
  report: ScanReport;
  mock: boolean;
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

// Once a scan is created from mock data, every later call for that session stays on mock data.
// A scan that started on the real API never switches to mock: its failures are shown as errors.
let mockSession = import.meta.env.VITE_MOCK === "1";
const mockApproved = new Set<string>();

export function isMockSession() {
  return mockSession;
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
  if (!mockSession) {
    try {
      const r = await request<Omit<ScanResponse, "mock">>(path, init, validScan);
      return { ...r, mock: false };
    } catch (e) {
      if (!(e instanceof ApiUnavailable)) throw e;
      mockSession = true;
    }
  }
  return createMockScan(name);
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

// A GitHub scan only works on the real API: the mock has no copy of someone else's repo.
export async function githubScan(url: string): Promise<ScanResponse> {
  mockApproved.clear();
  try {
    const r = await request<Omit<ScanResponse, "mock">>(
      "/api/scans/github",
      { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url }) },
      validScan,
    );
    mockSession = false;
    return { ...r, mock: false };
  } catch (e) {
    if (e instanceof ApiUnavailable) throw new Error("The scan server is offline, so GitHub repos cannot be fetched. Try the demo shop.");
    throw e;
  }
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
  const r = await request<Omit<PatchResponse, "mock">>(`/api/scans/${encodeURIComponent(id)}/patches`, { method: "POST" }, validPatches);
  return { ...r, mock: false };
}

export async function approve(id: string, patchId: string): Promise<string[]> {
  if (mockSession) {
    mockApproved.add(patchId);
    return [...mockApproved];
  }
  const r = await request<{ approved: string[] }>(
    `/api/scans/${encodeURIComponent(id)}/patches/${encodeURIComponent(patchId)}/approve`,
    { method: "POST" },
    validApprove,
  );
  return r.approved;
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
  return request<DownloadResponse>(`/api/scans/${encodeURIComponent(id)}/download`, { method: "GET" }, validDownload);
}
