import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

export interface RecordedRequest {
  method: string;
  /** path + query, e.g. /api/secrets/abc?k=xyz */
  url: string;
  headers: IncomingMessage["headers"];
  /** raw body string ("" when empty) */
  body: string;
}

export type Responder = (
  req: RecordedRequest,
  res: ServerResponse,
) => unknown;

export interface MockServer {
  baseUrl: string;
  requests: RecordedRequest[];
  setResponder(fn: Responder): void;
  close(): Promise<void>;
}

/**
 * In-process HTTP server for wire-format assertions. Records every request
 * verbatim; responses are driven by the current responder.
 */
export async function startMockServer(): Promise<MockServer> {
  let responder: Responder = (_req, res) => {
    res.writeHead(500, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "no responder configured" }));
  };
  const requests: RecordedRequest[] = [];

  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const recorded: RecordedRequest = {
        method: req.method ?? "",
        url: req.url ?? "",
        headers: req.headers,
        body: Buffer.concat(chunks).toString("utf8"),
      };
      requests.push(recorded);
      void responder(recorded, res);
    });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;

  return {
    baseUrl: `http://127.0.0.1:${port}`,
    requests,
    setResponder: (fn) => {
      responder = fn;
    },
    close: () => new Promise((resolve, reject) => server.close((e) => (e ? reject(e) : resolve()))),
  };
}

/** Convenience: respond with JSON. */
export function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}
