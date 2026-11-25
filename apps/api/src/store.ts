import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { gzipSync, gunzipSync } from "node:zlib";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand, PutCommand } from "@aws-sdk/lib-dynamodb";
import type { RepoSnapshot, ScanReport, GuardResult, DiffLine, Patch } from "@siidekick/engine";

export interface PatchEntry {
  patchId: string;
  patch: Patch;
  guard: GuardResult;
  diff: Array<{ path: string; lines: DiffLine[] }>;
  approved: boolean;
}

export interface ScanRecord {
  id: string;
  createdAt: string;
  repo: RepoSnapshot;
  report: ScanReport;
  patches?: PatchEntry[];
  after?: ScanReport;
  // snapshotAfter holds the repo state after patches were applied, so /download
  // can serve file contents. Kept internal (not returned by GET /api/scans/:id).
  snapshotAfter?: RepoSnapshot;
  // Set only by POST /api/scans/demo. Attack replay runs on records with this flag and nothing else.
  demo?: true;
  // Text files left out of a GitHub repo past the size caps; the report covers the rest.
  omitted?: number;
}

export interface Store {
  get(id: string): Promise<ScanRecord | null>;
  put(id: string, record: ScanRecord): Promise<void>;
}

// DynamoDB caps an item at 400 KB and a record carries the whole repo (up to 2 MB of text), so it is stored gzipped.
const MAX_ITEM_BYTES = 380_000;

export class RecordTooLargeError extends Error {}

function ttlSeconds(): number {
  return Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60;
}

export function createLocalStore(baseDir: string): Store {
  const scansDir = join(baseDir, "scans");
  return {
    async get(id: string): Promise<ScanRecord | null> {
      try {
        const raw = await readFile(join(scansDir, `${id}.json`), "utf8");
        return JSON.parse(raw) as ScanRecord;
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
        throw err;
      }
    },
    async put(id: string, record: ScanRecord): Promise<void> {
      await mkdir(scansDir, { recursive: true });
      await writeFile(join(scansDir, `${id}.json`), JSON.stringify(record), "utf8");
    },
  };
}

export function createDynamoStore(): Store {
  const client = new DynamoDBClient({});
  const doc = DynamoDBDocumentClient.from(client);
  const table = process.env.TABLE_NAME;
  if (!table) throw new Error("TABLE_NAME is required when STORAGE=dynamo");
  return {
    async get(id: string): Promise<ScanRecord | null> {
      const out = await doc.send(new GetCommand({ TableName: table, Key: { id } }));
      return out.Item ? (JSON.parse(gunzipSync(out.Item.blob as Uint8Array).toString("utf8")) as ScanRecord) : null;
    },
    async put(id: string, record: ScanRecord): Promise<void> {
      const blob = gzipSync(JSON.stringify(record));
      if (blob.length > MAX_ITEM_BYTES) throw new RecordTooLargeError("this repo is too large to store; try a smaller repo");
      await doc.send(new PutCommand({ TableName: table, Item: { id, blob, expiresAt: ttlSeconds() } }));
    },
  };
}

/** Reads env at call time so tests can point STORAGE/DATA_DIR at a temp dir. */
export function createStore(): Store {
  if (process.env.STORAGE === "dynamo") return createDynamoStore();
  const base = process.env.DATA_DIR || join(process.cwd(), ".data");
  return createLocalStore(base);
}
