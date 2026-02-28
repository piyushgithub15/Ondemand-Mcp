// ====== chat-proxy-mcp (FULL FIX + DEBUG) ======
process.on("unhandledRejection", (err) => {
  console.error("Unhandled Rejection (Debug):", err);
  process.exit(1);
});

process.on("uncaughtException", (err) => {
  console.error("Uncaught Exception (Debug):", err);
  process.exit(1);
});
console.log("leho test)
// [FIX] Import the correct 'Server' class and Request Schemas
const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
const {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} = require("@modelcontextprotocol/sdk/types.js");

const axios = require("axios");
const dotenv = require("dotenv");
const { z } = require("zod");
const express = require("express");
const { StreamableHTTPServerTransport } = require("@modelcontextprotocol/sdk/server/streamableHttp.js");
dotenv.config();

const HTTP_PORT = process.env.HTTP_PORT || 3000;

// ---- ENV CHECK ----
console.error("[DEBUG] Loaded ENV at startup:", {
  CHAT_API_KEY: process.env.CHAT_API_KEY ? "✅ present (will be ignored; URL key required)" : "❌ not used",
  CHAT_BASE_URL: process.env.CHAT_BASE_URL ? "✅ present" : "❌ missing",
  HTTP_PORT,
});

// ---- ALLOWED PATHS ----
const ALLOWED_PATHS = new Set([
  "/chat/v1/sessions",
  "/chat/v1/sessions/:sessionId",
  "/chat/v1/sessions/:sessionId/query",
  "/chat/v1/sessions/:sessionId/messages",
  "/chat/v1/sessions/:sessionId/messages/:messageId",
]);

function pathIsAllowed(requestPath) {
  if (ALLOWED_PATHS.has(requestPath)) return true;
  for (const p of ALLOWED_PATHS) {
    if (!p.includes(":")) continue;
    const regex = new RegExp(
      "^" +
        p
          .split("/")
          .map((seg) => (seg.startsWith(":") ? "[^/]+" : seg))
          .join("/") +
        "$"
    );
    if (regex.test(requestPath)) return true;
  }
  return false;
}

// ---- AUTH ----
// Strict: CHAT_API_KEY must come from URL (apikey or apiKey). CHAT_BASE_URL must come from .env

let cachedApiKey = null;

function getChatAuth(req) {
  const q = req?.query || {};
  const apiKey = q.apikey || q.apiKey || cachedApiKey;
  const baseUrl = process.env.CHAT_BASE_URL;

  console.debug("[DEBUG][getChatAuth] request URL:", req?.url);
  console.debug("[DEBUG][getChatAuth] raw query:", q);
  console.debug("[DEBUG][getChatAuth] apiKey found in query:", !!(q.apikey || q.apiKey));
  console.debug("[DEBUG][getChatAuth] CHAT_BASE_URL in env:", !!baseUrl);

  if (!apiKey) {
    console.error("[ERROR][getChatAuth] Missing CHAT_API_KEY in URL query. Use ?apikey=YOUR_KEY");
    throw new Error("Missing CHAT_API_KEY (must be passed via URL query)");
  }
  if (!baseUrl) {
    console.error("[ERROR][getChatAuth] Missing CHAT_BASE_URL in env");
    throw new Error("Missing CHAT_BASE_URL (not found in .env)");
  }

  cachedApiKey = apiKey; // store for internal MCP tool calls

  const safeAuth = {
    apiKeyPreview: apiKey.slice(0, 6) + "...",
    baseUrl,
  };
  console.debug("[DEBUG] Auth validated successfully:", safeAuth);

  return { apiKey, baseUrl };
}




// ---- ZOD SCHEMAS (FOR BACKEND VALIDATION) ----
// These are used inside the 'CallToolRequestSchema' handler
const ChatSessionCreateSchema = z.object({
  externalUserId: z.string().min(1),
  agentIds: z.array(z.string()).max(10).optional(),
  contextMetadata: z.array(z.any()).max(10).optional(),
  timeoutMs: z.number().int().positive().max(60000).default(15000),
});

const GetAllSessionsSchema = z.object({
  externalUserId: z.string().optional(),
  sort: z.enum(["asc", "desc"]).default("desc").optional(),
  cursor: z.string().optional(),
  limit: z.number().int().min(1).max(50).default(10).optional(),
  timeoutMs: z.number().int().positive().max(60000).default(15000),
});

const GetSessionByIdSchema = z.object({
  sessionId: z.string().min(1),
  timeoutMs: z.number().int().positive().max(60000).default(15000),
});

const UpdateSessionContextSchema = z.object({
  sessionId: z.string().min(1),
  contextMetadata: z.array(z.any()).max(10),
  timeoutMs: z.number().int().positive().max(60000).default(15000),
});

const SubmitQuerySchema = z.object({
  sessionId: z.string().min(1),
  query: z.string().min(1),
  endpointId: z.string().min(1),
  responseMode: z.enum(["sync", "stream", "webhook"]),
  reasoningMode: z
    .enum(["low", "medium", "high", "dynamicturbo"])
    .default("medium")
    .optional(),
  agentIds: z.array(z.string()).optional(),
  modelConfigs: z.any().optional(),
  timeoutMs: z.number().int().positive().max(60000).default(15000),
});

const GetAllMessagesSchema = z.object({
  sessionId: z.string().min(1),
  externalUserId: z.string().optional(),
  sort: z.enum(["asc", "desc"]).default("desc").optional(),
  cursor: z.string().optional(),
  limit: z.number().int().min(1).max(50).default(10).optional(),
  timeoutMs: z.number().int().positive().max(60000).default(15000),
});

const GetMessageByIdSchema = z.object({
  sessionId: z.string().min(1),
  messageId: z.string().min(1),
  timeoutMs: z.number().int().positive().max(60000).default(15000),
});

// ---- JSON SCHEMAS (FOR MCP INSPECTOR UI) ----
// These are the plain JSON schemas the inspector reads to build the UI
const ChatSessionCreateJsonSchema = {
  type: "object",
  properties: {
    externalUserId: {
      type: "string",
      description: "A unique ID for the user (e.g., 'user-12345')",
    },
    agentIds: {
      type: "array",
      items: { type: "string" },
      description: "Optional list of agent IDs to use for the session",
      default: [],
    },
    contextMetadata: {
      type: "array",
      description: "Optional array of key-value pairs for session context",
      default: [],
    },
    timeoutMs: {
      type: "number",
      description: "Request timeout in milliseconds",
      default: 15000,
    },
  },
  required: ["externalUserId"],
};

const GetAllSessionsJsonSchema = {
  type: "object",
  properties: {
    externalUserId: {
      type: "string",
      description: "Optional: Filter sessions by this user ID",
    },
    sort: {
      type: "string",
      enum: ["asc", "desc"],
      default: "desc",
      description: "Sort order for the session list",
    },
    cursor: {
      type: "string",
      description: "Optional: Pagination cursor for the next set of results",
    },
    limit: {
      type: "number",
      default: 10,
      description: "Number of sessions to return",
    },
    timeoutMs: {
      type: "number",
      default: 15000,
      description: "Request timeout in milliseconds",
    },
  },
};

const GetSessionByIdJsonSchema = {
  type: "object",
  properties: {
    sessionId: {
      type: "string",
      description: "The unique ID of the session to retrieve",
    },
    timeoutMs: {
      type: "number",
      default: 15000,
      description: "Request timeout in milliseconds",
    },
  },
  required: ["sessionId"],
};

const UpdateSessionContextJsonSchema = {
  type: "object",
  properties: {
    sessionId: {
      type: "string",
      description: "The unique ID of the session to update",
    },
    contextMetadata: {
      type: "array",
      description: "Array of key-value pairs to update session context",
      default: [], // Fixes UI error when field is empty
    },
    timeoutMs: {
      type: "number",
      default: 15000,
      description: "Request timeout in milliseconds",
    },
  },
  required: ["sessionId", "contextMetadata"],
};

const SubmitQueryJsonSchema = {
  type: "object",
  properties: {
    sessionId: {
      type: "string",
      description: "The unique ID of the session to query",
    },
    query: {
      type: "string",
      description: "The user's query text (e.g., 'hello')",
    },
    endpointId: {
      type: "string",
      description: "The ID of the endpoint to send the query to",
    },
    responseMode: {
      type: "string",
      enum: ["sync", "stream", "webhook"],
      description: "How to receive the response (sync, stream, or webhook)",
    },
    reasoningMode: {
      type: "string",
      enum: ["low", "medium", "high", "dynamicturbo"],
      default: "medium",
      description: "Controls the reasoning complexity and cost",
    },
    agentIds: {
      type: "array",
      items: { type: "string" },
      description: "Optional list of agent IDs to use for this query",
      default: [], // Fixes UI error when field is empty
    },
    modelConfigs: {
      type: "object",
      description: "Optional: Override model configurations for this query",
      default: {}, // Fixes UI error when field is empty
    },
    timeoutMs: {
      type: "number",
      default: 15000,
      description: "Request timeout in milliseconds",
    },
  },
  required: ["sessionId", "query", "endpointId", "responseMode"],
};

const GetAllMessagesJsonSchema = {
  type: "object",
  properties: {
    sessionId: {
      type: "string",
      description: "The unique ID of the session",
    },
    externalUserId: {
      type: "string",
      description: "Optional: Filter messages by this user ID",
    },
    sort: {
      type: "string",
      enum: ["asc", "desc"],
      default: "desc",
      description: "Sort order for the message list",
    },
    cursor: {
      type: "string",
      description: "Optional: Pagination cursor for the next set of results",
    },
    limit: {
      type: "number",
      default: 10,
      description: "Number of messages to return",
    },
    timeoutMs: {
      type: "number",
      default: 15000,
      description: "Request timeout in milliseconds",
    },
  },
  required: ["sessionId"],
};

const GetMessageByIdJsonSchema = {
  type: "object",
  properties: {
    sessionId: {
      type: "string",
      description: "The unique ID of the session",
    },
    messageId: {
      type: "string",
      description: "The unique ID of the message to retrieve",
    },
    timeoutMs: {
      type: "number",
      default: 15000,
      description: "Request timeout in milliseconds",
    },
  },
  required: ["sessionId", "messageId"],
};

// ---- MCP SERVER ----
// [FIX] Use 'Server' class, not 'McpServer'.
const server = new Server(
  {
    name: "chat-proxy-mcp",
    version: "2.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// ---- EXPRESS SETUP ----
const app = express();
app.use(express.json());

// ---- SHARED REQUEST LOGIC (HELPER) ----
// makeApiRequest now accepts req and res so we can read query and stream responses.
const makeApiRequest = async (
  method,
  path,
  inputArgs,
  bodyExtractor,
  req = null,
  res = null
) => {
  // read auth from request (apikey from URL) and env (baseUrl)
  const { apiKey, baseUrl } = getChatAuth(req);
  const { timeoutMs, ...rest } = inputArgs;

  if (!pathIsAllowed(path)) {
    console.error("[SECURITY] Blocked path:", path);
    throw new Error(`Path not allowed by security policy: ${path}`);
  }

  const url = `${baseUrl}${path}`;
  const data = method !== "GET" ? bodyExtractor(rest) : undefined;
  const params = method === "GET" ? rest : undefined;

  console.error(`[INFO] Preparing request -> ${method} ${url}`);
  console.error("[INFO] Params:", params);
  console.error("[INFO] Data:", !!data);
  console.error("[INFO] Using header apikey present:", !!apiKey);

  try {
    // STREAM MODE (live output to HTTP client)
    if (rest.responseMode === "stream" && res) {
      console.error("[STREAM] Live streaming to client...");
      const response = await axios({
        method,
        url,
        params,
        data,
        headers: { apikey: apiKey, "Content-Type": "application/json" },
        timeout: timeoutMs,
        responseType: "stream",
        validateStatus: () => true,
      });

      console.error("[STREAM] Downstream status:", response.status);
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.status(response.status);

      response.data.on("data", (chunk) => {
        try {
          res.write(chunk);
        } catch (err) {
          console.error("[STREAM WRITE ERROR]", err.message);
        }
      });
      response.data.on("end", () => {
        res.end();
      });
      response.data.on("error", (err) => {
        console.error("[STREAM ERROR]", err.message);
        if (!res.headersSent) res.status(500);
        res.end("\n[Stream Error: " + err.message + "]");
      });
      return; // handled via streaming
    }

    // SYNC / NORMAL
    const response = await axios.request({
      method,
      url,
      params,
      data,
      headers: { apikey: apiKey, "Content-Type": "application/json" },
      timeout: timeoutMs,
      validateStatus: () => true,
    });

    console.error("[INFO] Downstream response status:", response.status);
    const payload = JSON.stringify(response.data, null, 2);
    return {
      content: [{ type: "text", text: payload }],
      isError: response.status >= 400,
    };
  } catch (e) {
    console.error(`[ERROR] Request failed: ${e.message}`);
    // Show stack in debug to help pairing
    console.error(e.stack || e);
    return {
      content: [{ type: "text", text: `Error: ${e.message}` }],
      isError: true,
    };
  }
};

// ---- REGISTER TOOLS WITH 'setRequestHandler' ----
// 1. Handler for 'ListToolsRequestSchema'
server.setRequestHandler(ListToolsRequestSchema, async () => {
  console.error("[MCP] ListToolsRequestSchema called");
  return {
    tools: [
      {
        name: "chat.v1.sessions.create",
        description: "Creates a new chat session.",
        inputSchema: ChatSessionCreateJsonSchema,
      },
      {
        name: "chat.v1.sessions.get_all",
        description: "Lists all sessions.",
        inputSchema: GetAllSessionsJsonSchema,
      },
      {
        name: "chat.v1.session.get_by_id",
        description: "Get a session by ID.",
        inputSchema: GetSessionByIdJsonSchema,
      },
      {
        name: "chat.v1.session.update_context",
        description: "Updates session metadata.",
        inputSchema: UpdateSessionContextJsonSchema,
      },
      {
        name: "chat.v1.session.submit_query",
        description: "Submits a query to an agent.",
        inputSchema: SubmitQueryJsonSchema,
      },
      {
        name: "chat.v1.messages.get_all",
        description: "Get all messages of a session.",
        inputSchema: GetAllMessagesJsonSchema,
      },
      {
        name: "chat.v1.message.get_by_id",
        description: "Get message by ID.",
        inputSchema: GetMessageByIdJsonSchema,
      },
    ],
  };
});

// Helper for Zod validation error
function createErrorResponse(zodError) {
  console.error("[VALIDATION ERROR]", zodError);
  return {
    content: [{ type: "text", text: `Invalid input: ${zodError.message}` }],
    isError: true,
  };
}

// 2. Handler for 'CallToolRequestSchema'
// Note: signature expects (request, req, res) when used with StreamableHTTPServerTransport
server.setRequestHandler(CallToolRequestSchema, async (request, req, res) => {
  const { name, arguments: args } = request.params;
  console.error(`[MCP] CallToolRequestSchema -> ${name}`, {
    argsPreview: args ? Object.keys(args).slice(0, 10) : [],
    requestId: request.id || "unknown",
  });

  try {
    switch (name) {
      case "chat.v1.sessions.create": {
        const validation = ChatSessionCreateSchema.safeParse(args);
        if (!validation.success) return createErrorResponse(validation.error);
        return makeApiRequest(
          "POST",
          "/chat/v1/sessions",
          validation.data,
          ({ timeoutMs, ...d }) => d,
          req,
          res
        );
      }

      case "chat.v1.sessions.get_all": {
        const validation = GetAllSessionsSchema.safeParse(args);
        if (!validation.success) return createErrorResponse(validation.error);
        return makeApiRequest("GET", "/chat/v1/sessions", validation.data, (x) => x, req, res);
      }

      case "chat.v1.session.get_by_id": {
        const validation = GetSessionByIdSchema.safeParse(args);
        if (!validation.success) return createErrorResponse(validation.error);
        const path = `/chat/v1/sessions/${encodeURIComponent(validation.data.sessionId)}`;
        return makeApiRequest("GET", path, validation.data, (x) => x, req, res);
      }

      case "chat.v1.session.update_context": {
        const validation = UpdateSessionContextSchema.safeParse(args);
        if (!validation.success) return createErrorResponse(validation.error);
        const path = `/chat/v1/sessions/${encodeURIComponent(validation.data.sessionId)}`;
        return makeApiRequest(
          "PATCH",
          path,
          validation.data,
          ({ sessionId, timeoutMs, ...d }) => d,
          req,
          res
        );
      }

      case "chat.v1.session.submit_query": {
        const validation = SubmitQuerySchema.safeParse(args);
        if (!validation.success) return createErrorResponse(validation.error);
        const path = `/chat/v1/sessions/${encodeURIComponent(validation.data.sessionId)}/query`;
        return makeApiRequest(
          "POST",
          path,
          validation.data,
          ({ sessionId, timeoutMs, ...d }) => d,
          req,
          res
        );
      }

      case "chat.v1.messages.get_all": {
        const validation = GetAllMessagesSchema.safeParse(args);
        if (!validation.success) return createErrorResponse(validation.error);
        const path = `/chat/v1/sessions/${encodeURIComponent(validation.data.sessionId)}/messages`;
        return makeApiRequest("GET", path, validation.data, (x) => x, req, res);
      }

      case "chat.v1.message.get_by_id": {
        const validation = GetMessageByIdSchema.safeParse(args);
        if (!validation.success) return createErrorResponse(validation.error);
        const path = `/chat/v1/sessions/${encodeURIComponent(validation.data.sessionId)}/messages/${encodeURIComponent(validation.data.messageId)}`;
        return makeApiRequest("GET", path, validation.data, (x) => x, req, res);
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    console.error(`[ERROR] Tool ${name} failed:`, error);
    return {
      content: [{ type: "text", text: `Tool execution failed: ${error.message}` }],
      isError: true,
    };
  }
});

// ---- HTTP ENDPOINT ----
app.post("/mcp", async (req, res) => {
  console.debug("\n========== [DEBUG] Incoming /mcp Request ==========");
  console.debug("[DEBUG] URL:", req.url);
  console.debug("[DEBUG] Method:", req.method);
  console.debug("[DEBUG] Headers preview:", {
    host: req.headers.host,
    "content-type": req.headers["content-type"],
  });
  console.debug("[DEBUG] Query:", req.query);

  try {
    const { apiKey, baseUrl } = getChatAuth(req);

    // Inject into environment for downstream internal calls (safe)
    process.env.CHAT_API_KEY = apiKey;
    process.env.CHAT_BASE_URL = baseUrl;

    console.debug("[DEBUG] Connecting server to transport...");
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });

    await server.connect(transport);
    console.debug("[DEBUG] Connected. Passing request to transport.handleRequest...");
    await transport.handleRequest(req, res, req.body);
    console.debug("[DEBUG] transport.handleRequest completed (if streaming, completion may be delayed).");
    console.debug("========== [DEBUG] /mcp END ==========\n");
  } catch (error) {
    console.error("MCP request error:", error.message);
    if (!res.headersSent) res.status(500).json({ error: error.message });
    else res.end();
  }
});

// ---- START ----
app.listen(HTTP_PORT, () => {
  console.error(`[SUCCESS] Streamable MCP Proxy running at http://localhost:${HTTP_PORT}`);
});
