import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2, Context, Handler } from "aws-lambda";
import { SFNClient, StartExecutionCommand } from "@aws-sdk/client-sfn";
import { makeRouter } from "./router.js";
import { createStore } from "./store.js";
import { artifactsFromEnv } from "./artifacts.js";

const pipelineArn = process.env.PIPELINE_ARN;
const sfn = pipelineArn ? new SFNClient({}) : null;

const router = makeRouter({
  store: createStore(),
  artifacts: artifactsFromEnv() ?? undefined,
  startPipeline: sfn
    ? async (scanId) => {
        const out = await sfn.send(
          new StartExecutionCommand({ stateMachineArn: pipelineArn, name: `scan-${scanId}-${Date.now()}`, input: JSON.stringify({ scanId }) }),
        );
        return out.executionArn!;
      }
    : undefined,
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
  try {
    const body = event.body ? JSON.parse(event.body) : undefined;
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
