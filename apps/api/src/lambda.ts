import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2, Context, Handler } from "aws-lambda";
import { makeRouter } from "./router.js";
import { createStore } from "./store.js";
import { bedrockConverse, type ConverseFn } from "./ai.js";
import { awsVerifyBackend, evaluateJob, type VerifyBackend } from "./verify.js";

/** Built once per Lambda instance, on first use. */
function lazy<T>(make: () => Promise<T>): () => Promise<T> {
  let p: Promise<T> | null = null;
  return () => (p ??= make().catch((err) => ((p = null), Promise.reject(err))));
}

const env = process.env;
// The evaluate function gets only the bucket (giving it the state machine's ARN would be a stack cycle);
// the API needs both, since it starts executions.
const verifyBackend: (() => Promise<VerifyBackend>) | undefined = env.ARTIFACT_BUCKET
  ? lazy(() => awsVerifyBackend({ bucket: env.ARTIFACT_BUCKET!, stateMachineArn: env.STATE_MACHINE_ARN ?? "" }))
  : undefined;
const converse: (() => Promise<ConverseFn>) | undefined = env.BEDROCK_MODEL_ID ? lazy(() => bedrockConverse(env.BEDROCK_REGION)) : undefined;

const router = makeRouter({
  store: createStore(),
  ai: converse ? { modelId: env.BEDROCK_MODEL_ID!, converse } : undefined,
  verify: env.STATE_MACHINE_ARN ? verifyBackend : undefined,
  siteUrl: env.SITE_URL,
});

function headers(): Record<string, string> {
  return {
    "content-type": "application/json",
    "cache-control": "no-store",
  };
}

export const handler: Handler = async (
  event: APIGatewayProxyEventV2,
  _context: Context,
): Promise<APIGatewayProxyResultV2> => {
  let body: unknown;
  try {
    const raw = event.body && event.isBase64Encoded ? Buffer.from(event.body, "base64").toString("utf8") : event.body;
    body = raw ? JSON.parse(raw) : undefined;
  } catch {
    return { statusCode: 400, headers: headers(), body: JSON.stringify({ error: "body must be JSON" }) };
  }
  try {
    const result = await router.handle({
      method: event.requestContext.http.method,
      path: event.rawPath || "/",
      body,
    });
    return {
      statusCode: result.status,
      headers: headers(),
      body: JSON.stringify(result.body),
    };
  } catch (err) {
    console.error(err);
    return { statusCode: 500, headers: headers(), body: JSON.stringify({ error: "internal" }) };
  }
};

/** Step Functions' "Evaluate" task: applies the trust rule to the CodeBuild output and stores the verdict. */
export const evaluateHandler: Handler = async (event: { jobId: string; error?: { Error?: string; Cause?: string } }) => {
  if (!verifyBackend) throw new Error("ARTIFACT_BUCKET must be set");
  if (typeof event?.jobId !== "string" || !/^[0-9a-f-]{36}$/i.test(event.jobId)) throw new Error("invalid jobId");
  const verdict = await evaluateJob(await verifyBackend(), event);
  return { jobId: verdict.jobId, status: verdict.status, headline: verdict.headline };
};
