import type { DiffLine } from "../../../../packages/engine/src/diffGuard";
import type { GuardResult, Patch, RepoFile, ScanReport } from "../../../../packages/engine/src/types";
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

export async function download(id: string): Promise<DownloadResponse> {
  if (mockSession) return mockDownload([...mockApproved]);
  return request<DownloadResponse>(`/api/scans/${encodeURIComponent(id)}/download`, { method: "GET" }, validDownload);
}
