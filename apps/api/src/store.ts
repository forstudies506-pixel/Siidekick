import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { gzipSync, gunzipSync } from "node:zlib";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand, PutCommand } from "@aws-sdk/lib-dynamodb";
import { createClient } from "redis";
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
  // Set for scans started from a GitHub URL, so a pull request can target the same repo and branch.
  source?: { type: "github"; owner: string; repo: string; ref: string };
  // Bedrock explanations already generated, keyed "<checkId>:<index>:<lang>", so each costs one model call.
  explanations?: Record<string, import("./ai.js").ExplainResult>;
  // The most recent isolated verification run for this scan.
  latestVerify?: { jobId: string; startedAt: string; approved: string[] };
}

export interface Store {
  /** Which backend holds records; /api/health reports it so a deploy shows whether links survive. */
  readonly kind: "local" | "dynamo" | "upstash" | "redis";
  get(id: string): Promise<ScanRecord | null>;
  put(id: string, record: ScanRecord): Promise<void>;
}

// DynamoDB caps an item at 400 KB. A record carries the whole repo, so it is stored gzipped, and a record that is
// still too big goes to S3 (scans/<id>.json.gz, expiring with the same 7-day lifecycle) with a pointer in DynamoDB.
const MAX_ITEM_BYTES = 380_000;
const MAX_S3_BYTES = 60_000_000;

export class RecordTooLargeError extends Error {}

const TTL_SECONDS = 7 * 24 * 60 * 60;

function ttlSeconds(): number {
  return Math.floor(Date.now() / 1000) + TTL_SECONDS;
}

export function createLocalStore(baseDir: string): Store {
  const scansDir = join(baseDir, "scans");
  return {
    kind: "local",
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
  const bucket = process.env.ARTIFACT_BUCKET;
  let s3Cache: Promise<{ s3: import("@aws-sdk/client-s3").S3Client; PutObjectCommand: typeof import("@aws-sdk/client-s3").PutObjectCommand; GetObjectCommand: typeof import("@aws-sdk/client-s3").GetObjectCommand }> | undefined;
  // Loaded on first use, so small scans never pay for the S3 client.
  const s3Client = () =>
    (s3Cache ??= import("@aws-sdk/client-s3").then(({ S3Client, PutObjectCommand, GetObjectCommand }) => ({ s3: new S3Client({}), PutObjectCommand, GetObjectCommand })));
  return {
    kind: "dynamo",
    async get(id: string): Promise<ScanRecord | null> {
      const out = await doc.send(new GetCommand({ TableName: table, Key: { id } }));
      if (!out.Item) return null;
      let blob = out.Item.blob as Uint8Array | undefined;
      if (!blob && typeof out.Item.s3Key === "string" && bucket) {
        const { s3, GetObjectCommand } = await s3Client();
        const obj = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: out.Item.s3Key }));
        blob = obj.Body ? await obj.Body.transformToByteArray() : undefined;
      }
      return blob ? (JSON.parse(gunzipSync(blob).toString("utf8")) as ScanRecord) : null;
    },
    async put(id: string, record: ScanRecord): Promise<void> {
      const blob = gzipSync(JSON.stringify(record));
      if (blob.length <= MAX_ITEM_BYTES) {
        await doc.send(new PutCommand({ TableName: table, Item: { id, blob, expiresAt: ttlSeconds() } }));
        return;
      }
      if (!bucket || blob.length > MAX_S3_BYTES) throw new RecordTooLargeError("this repo is too large to store; try a smaller repo");
      const s3Key = `scans/${id}.json.gz`;
      const { s3, PutObjectCommand } = await s3Client();
      await s3.send(new PutObjectCommand({ Bucket: bucket, Key: s3Key, Body: blob, ContentType: "application/gzip" }));
      await doc.send(new PutCommand({ TableName: table, Item: { id, s3Key, expiresAt: ttlSeconds() } }));
    },
  };
}

// Upstash free plan caps a request at 10 MB; a gzipped record is far below this in practice.
const MAX_UPSTASH_BYTES = 5_000_000;

/**
 * Upstash Redis over its REST API, so the Vercel build keeps records across function instances.
 * One record per key, gzipped and base64-encoded, expiring after 7 days like the DynamoDB store.
 */
export function createUpstashStore(opts: { url: string; token: string; fetch?: typeof fetch }): Store {
  const doFetch = opts.fetch ?? fetch;
  const key = (id: string) => `siidekick:scan:${id}`;
  async function command(args: Array<string | number>): Promise<unknown> {
    const res = await doFetch(opts.url, {
      method: "POST",
      headers: { authorization: `Bearer ${opts.token}`, "content-type": "application/json" },
      body: JSON.stringify(args),
    });
    let out: { result?: unknown; error?: string };
    try {
      out = (await res.json()) as typeof out;
    } catch {
      throw new Error(`upstash: HTTP ${res.status}`);
    }
    if (!res.ok || out.error) throw new Error(`upstash: ${out.error ?? `HTTP ${res.status}`}`);
    return out.result;
  }
  return {
    kind: "upstash",
    async get(id: string): Promise<ScanRecord | null> {
      const value = await command(["GET", key(id)]);
      if (value == null) return null;
      return JSON.parse(gunzipSync(Buffer.from(String(value), "base64")).toString("utf8")) as ScanRecord;
    },
    async put(id: string, record: ScanRecord): Promise<void> {
      const value = gzipSync(JSON.stringify(record)).toString("base64");
      if (value.length > MAX_UPSTASH_BYTES) throw new RecordTooLargeError("this repo is too large to store; try a smaller repo");
      await command(["SET", key(id), value, "EX", TTL_SECONDS]);
    },
  };
}

/** Upstash's own names, or the KV_* names some Vercel storage integrations set. */
export function upstashEnv(): { url: string; token: string } | null {
  const url = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;
  return url && token ? { url, token } : null;
}

// The free Redis Cloud database is 30 MB in all, so one record may take at most 1 MB of it.
const MAX_REDIS_BYTES = 1_000_000;

/** The two commands the Redis store uses; `createClient` from `redis` satisfies it, tests pass a fake. */
export interface RedisLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, opts: { expiration: { type: "EX"; value: number } }): Promise<unknown>;
}

/**
 * Redis over its own TCP protocol (`redis://` or `rediss://`), for the Redis Cloud database the Vercel
 * integration connects. Same record format and 7-day expiry as the Upstash store.
 */
export function createRedisStore(opts: { url: string; connect?: () => Promise<RedisLike> }): Store {
  type Client = ReturnType<typeof newClient>;
  const newClient = () =>
    createClient({
      url: opts.url,
      disableOfflineQueue: true,
      socket: { connectTimeout: 5000, reconnectStrategy: false },
    });
  let client: Client | null = null;
  let pending: Promise<Client> | null = null;
  // One socket per function instance, reused across requests; concurrent requests share one connect,
  // since the free plan caps connections. A closed socket (instance frozen and thawed, server dropped
  // it) is replaced rather than retried in the background.
  const connect =
    opts.connect ??
    (() => {
      if (client?.isReady) return Promise.resolve(client);
      if (pending) return pending;
      if (client?.isOpen) client.destroy();
      const next = newClient();
      // Without a listener a dropped socket would crash the process. The next request reconnects.
      next.on("error", () => {});
      pending = next
        .connect()
        .then(() => (client = next))
        .finally(() => (pending = null));
      return pending;
    });
  const key = (id: string) => `siidekick:scan:${id}`;
  return {
    kind: "redis",
    async get(id: string): Promise<ScanRecord | null> {
      const value = await (await connect()).get(key(id));
      if (value == null) return null;
      return JSON.parse(gunzipSync(Buffer.from(value, "base64")).toString("utf8")) as ScanRecord;
    },
    async put(id: string, record: ScanRecord): Promise<void> {
      const value = gzipSync(JSON.stringify(record)).toString("base64");
      if (value.length > MAX_REDIS_BYTES) throw new RecordTooLargeError("this repo is too large to store; try a smaller repo");
      await (await connect()).set(key(id), value, { expiration: { type: "EX", value: TTL_SECONDS } });
    },
  };
}

/** `KV_REDIS_URL` is what the Vercel Redis integration sets with the `KV` prefix. */
export function redisUrl(): string | null {
  return process.env.KV_REDIS_URL || process.env.REDIS_URL || null;
}

/** Reads env at call time so tests can point STORAGE/DATA_DIR at a temp dir. */
export function createStore(): Store {
  if (process.env.STORAGE === "dynamo") return createDynamoStore();
  if (process.env.STORAGE === "upstash") {
    const env = upstashEnv();
    if (!env) throw new Error("UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN are required when STORAGE=upstash");
    return createUpstashStore(env);
  }
  if (process.env.STORAGE === "redis") {
    const url = redisUrl();
    if (!url) throw new Error("KV_REDIS_URL or REDIS_URL is required when STORAGE=redis");
    return createRedisStore({ url });
  }
  const base = process.env.DATA_DIR || join(process.cwd(), ".data");
  return createLocalStore(base);
}
