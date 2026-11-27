import { GetObjectCommand, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { gzipSync, gunzipSync } from "node:zlib";

/**
 * The pipeline's S3 bucket: full repo snapshots, oversized scan records, verification inputs and
 * results, change reports and SBOMs. Objects are private and server-side encrypted; the bucket's
 * lifecycle rule removes them after the same 7-day window as the scan records.
 */
export interface Artifacts {
  readonly bucket: string;
  putJson(key: string, value: unknown, opts?: { gzip?: boolean }): Promise<void>;
  getJson<T>(key: string): Promise<T | null>;
  putText(key: string, text: string, contentType: string): Promise<void>;
}

export function s3Artifacts(bucket: string, client: Pick<S3Client, "send"> = new S3Client({})): Artifacts {
  return {
    bucket,
    async putJson(key, value, opts) {
      const raw = Buffer.from(JSON.stringify(value));
      await client.send(
        new PutObjectCommand({
          Bucket: bucket,
          Key: key,
          Body: opts?.gzip ? gzipSync(raw) : raw,
          ContentType: "application/json",
          ...(opts?.gzip ? { ContentEncoding: "gzip" } : {}),
          ServerSideEncryption: "AES256",
        }),
      );
    },
    async getJson<T>(key: string) {
      try {
        const out = await client.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
        const bytes = Buffer.from(await out.Body!.transformToByteArray());
        const text = (bytes[0] === 0x1f && bytes[1] === 0x8b ? gunzipSync(bytes) : bytes).toString("utf8");
        return JSON.parse(text) as T;
      } catch (err) {
        if ((err as { name?: string }).name === "NoSuchKey") return null;
        throw err;
      }
    },
    async putText(key, text, contentType) {
      await client.send(new PutObjectCommand({ Bucket: bucket, Key: key, Body: text, ContentType: contentType, ServerSideEncryption: "AES256" }));
    },
  };
}

export function artifactsFromEnv(): Artifacts | null {
  const bucket = process.env.ARTIFACTS_BUCKET;
  return bucket ? s3Artifacts(bucket) : null;
}
