import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2, Context, Handler } from "aws-lambda";
import { makeRouter } from "./router.js";
import { createStore } from "./store.js";

const router = makeRouter({ store: createStore() });

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
