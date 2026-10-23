
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS"
};

const MAX_IMAGE_BYTES = 8 * 1024 * 1024;
const MAX_TITLE_LENGTH = 180;
const MAX_SUMMARY_LENGTH = 500;
const SESSION_SECONDS = 60 * 60 * 8;
const BUCKET = "analysis-media";
const IMAGE_TYPES = new Set([
  "image/jpeg",
  "image/png",
  "image/webp"
]);

function response(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json",
      "Cache-Control": "no-store"
    }
  });
}

function getPath(event) {
  const candidates = [
    event.path,
    new URL(event.rawUrl || "https://localhost").pathname
  ];

  for (let path of candidates) {
    if (!path) continue;

    path = path.replace(/\/+$/, "");

    const functionIndex = path.indexOf("/.netlify/functions/api");
    if (functionIndex !== -1) {
      path = path.slice(functionIndex + "/.netlify/functions/api".length);
      return path || "/";
    }

    const apiIndex = path.indexOf("/api/");
    if (apiIndex !== -1) return path.slice(apiIndex + 4);

    if (path === "/api") return "/";
  }

  return "/";
}

function getMethod(event) {
  return (
    event.httpMethod ||
    event.requestContext?.http?.method ||
    "GET"
  ).toUpperCase();
}

function getSupabaseConfig() {
  const url = process.env.SUPABASE_URL?.replace(/\/+$/, "");
  const key = process.env.SUPABASE_SECRET_KEY;

  if (!url || !key) {
    throw new Error("Supabase environment variables are missing.");
  }

  return { url, key };
}

async function supabase(path, options = {}) {
  const { url, key } = getSupabaseConfig();

  const headers = {
    apikey: key,
    Authorization: `Bearer ${key}`,
    ...options.headers
  };

  if (options.body && !(options.body instanceof ArrayBuffer)) {
    headers["Content-Type"] ??= "application/json";
  }

  const result = await fetch(`${url}${path}`, {
    ...options,
    headers
  });

  const text = await result.text();
  let data = null;

  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }

  if (!result.ok) {
    console.error("Supabase request failed:", result.status, data);
    throw new Error(
      typeof data === "object" && data?.message
        ? data.message
        : `Storage or database request failed (${result.status}).`
    );
  }

  return data;
}

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function signToken(payload) {
  const secret = process.env.SESSION_SECRET;

  if (!secret || secret.length < 32) {
    throw new Error("SESSION_SECRET must be set to at least 32 characters.");
  }

  const encoded = base64url(
    new TextEncoder().encode(JSON.stringify(payload))
  );

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(encoded)
  );

  return `${encoded}.${base64url(new Uint8Array(signature))}`;
}

async function verifyToken(token) {
  const secret = process.env.SESSION_SECRET;
  if (!secret || !token) return false;

  const parts = token.split(".");
  if (parts.length !== 2) return false;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const signature = parts[1]
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padded = signature + "=".repeat((4 - signature.length % 4) % 4);
  const binary = atob(padded);
  const signatureBytes = Uint8Array.from(
    binary,
    character => character.charCodeAt(0)
  );

  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    signatureBytes,
    new TextEncoder().encode(parts[0])
  );

  if (!valid) return false;

  try {
    const payloadText = atob(
      parts[0].replace(/-/g, "+").replace(/_/g, "/") +
      "=".repeat((4 - parts[0].length % 4) % 4)
    );

    const payload = JSON.parse(payloadText);
    return payload.exp > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

async function requireAdmin(event) {
  const authorization = event.headers?.authorization ||
    event.headers?.Authorization || "";

  const token = authorization.startsWith("Bearer ")
    ? authorization.slice(7)
    : "";

  if (!(await verifyToken(token))) {
    throw Object.assign(new Error("Your session is invalid or expired."), {
      status: 401
    });
  }
}

function parseBody(event) {
  if (!event.body) return {};

  try {
    return JSON.parse(
      event.isBase64Encoded
        ? atob(event.body)
        : event.body
    );
  } catch {
    throw Object.assign(new Error("Invalid JSON request body."), {
      status: 400
    });
  }
}

function validVideoUrl(value) {
  if (!value) return null;

  try {
    const url = new URL(value);
    const host = url.hostname.toLowerCase();

    if (
      url.protocol !== "https:" ||
      ![
        "youtube.com",
        "www.youtube.com",
        "m.youtube.com",
        "youtu.be",
        "www.youtube-nocookie.com"
      ].includes(host)
    ) {
      return false;
    }

    return url.toString();
  } catch {
    return false;
  }
}

function cleanAnalysis(body) {
  const title = String(body.title || "").trim();
  const summary = String(body.summary || "").trim();
  const content = String(body.content || "").trim();
  const market = String(body.market || "Forex").trim();
  const status = body.status === "published" ? "published" : "draft";
  const video = validVideoUrl(body.video_url || body.videoUrl || "");

  if (!title || title.length > MAX_TITLE_LENGTH) {
    throw Object.assign(
      new Error("Title is required and must be 180 characters or fewer."),
      { status: 400 }
    );
  }

  if (summary.length > MAX_SUMMARY_LENGTH) {
    throw Object.assign(
      new Error("Summary must be 500 characters or fewer."),
      { status: 400 }
    );
  }

  if (video === false) {
    throw Object.assign(
      new Error("Video links must be valid HTTPS YouTube URLs."),
      { status: 400 }
    );
  }

  const allowedMarkets = new Set(["Forex", "Crypto", "Gold", "Other"]);

  if (!allowedMarkets.has(market)) {
    throw Object.assign(new Error("Invalid market category."), {
      status: 400
    });
  }

  return {
    title,
    summary,
    content,
    market,
    status,
    video_url: video,
    updated_at: new Date().toISOString(),
    ...(status === "published"
      ? { published_at: new Date().toISOString() }
      : {})
  };
}

async function createSignedImageUrl(path) {
  const encodedPath = path
    .split("/")
    .map(encodeURIComponent)
    .join("/");

  const result = await supabase(
    `/storage/v1/object/sign/${BUCKET}/${encodedPath}`,
    {
      method: "POST",
      body: JSON.stringify({ expiresIn: 3600 })
    }
  );

  const signed = result?.signedURL || result?.signedUrl;

  if (!signed) return null;

  const { url } = getSupabaseConfig();
  return signed.startsWith("http")
    ? signed
    : `${url}/storage/v1${signed.startsWith("/") ? "" : "/"}${signed}`;
}

async function attachMedia(analysis) {
  const media = await supabase(
    `/rest/v1/analysis_media?analysis_id=eq.${analysis.id}&select=id,storage_path,media_type,alt_text,sort_order&order=sort_order.asc`
  );

  const items = await Promise.all(
    (media || []).map(async item => ({
      ...item,
      url: item.media_type === "image"
        ? await createSignedImageUrl(item.storage_path)
        : null
    }))
  );

  return { ...analysis, media: items };
}

async function publicAnalyses() {
  const rows = await supabase(
    "/rest/v1/analyses?status=eq.published&select=*&order=published_at.desc.nullslast,created_at.desc"
  );

  return Promise.all((rows || []).map(attachMedia));
}

async function saveMediaRecords(analysisId, mediaItems) {
  if (!Array.isArray(mediaItems)) return;

  await supabase(
    `/rest/v1/analysis_media?analysis_id=eq.${analysisId}`,
    { method: "DELETE" }
  );

  const rows = mediaItems
    .filter(item => item && typeof item.storage_path === "string")
    .slice(0, 20)
    .map((item, index) => ({
      analysis_id: analysisId,
      storage_path: item.storage_path,
      media_type: "image",
      alt_text: String(item.alt_text || "").slice(0, 300),
      sort_order: Number.isInteger(item.sort_order)
        ? item.sort_order
        : index
    }));

  if (rows.length) {
    await supabase("/rest/v1/analysis_media", {
      method: "POST",
      headers: { Prefer: "return=minimal" },
      body: JSON.stringify(rows)
    });
  }
}

export default async function handler(event) {
  const method = getMethod(event);
  const path = getPath(event);

  if (method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  try {
    if (method === "GET" && path === "/health") {
      return response({
        ok: true,
        service: "dreamverse-market-analysis-api"
      });
    }

    if (method === "POST" && path === "/admin/login") {
      const body = parseBody(event);
      const expected = process.env.ADMIN_PASSWORD;

      if (!expected) {
        throw new Error("ADMIN_PASSWORD is not configured.");
      }

      if (
        typeof body.password !== "string" ||
        body.password !== expected
      ) {
        return response({ error: "Incorrect password." }, 401);
      }

      const token = await signToken({
        role: "admin",
        exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS
      });

      return response({ token, expiresIn: SESSION_SECONDS });
    }

    if (method === "GET" && path === "/analyses") {
      return response({ analyses: await publicAnalyses() });
    }

    const publicDetail = path.match(/^\/analyses\/([0-9a-f-]{36})$/i);

    if (method === "GET" && publicDetail) {
      const rows = await supabase(
        `/rest/v1/analyses?id=eq.${publicDetail[1]}&status=eq.published&select=*`
      );

      if (!rows?.length) {
        return response({ error: "Analysis not found." }, 404);
      }

      return response({ analysis: await attachMedia(rows[0]) });
    }

    if (path.startsWith("/admin/")) {
      await requireAdmin(event);
    }

    if (method === "GET" && path === "/admin/analyses") {
      const rows = await supabase(
        "/rest/v1/analyses?select=*&order=created_at.desc"
      );

      return response({
        analyses: await Promise.all((rows || []).map(attachMedia))
      });
    }

    if (method === "POST" && path === "/admin/analyses") {
      const body = parseBody(event);
      const record = cleanAnalysis(body);

      const rows = await supabase("/rest/v1/analyses", {
        method: "POST",
        headers: { Prefer: "return=representation" },
        body: JSON.stringify(record)
      });

      const analysis = rows?.[0];

      if (!analysis) {
        throw new Error("The analysis could not be created.");
      }

      await saveMediaRecords(analysis.id, body.media);

      return response({ analysis: await attachMedia(analysis) }, 201);
    }

    const adminDetail = path.match(/^\/admin\/analyses\/([0-9a-f-]{36})$/i);

    if (adminDetail && method === "PUT") {
      const body = parseBody(event);
      const record = cleanAnalysis(body);

      const rows = await supabase(
        `/rest/v1/analyses?id=eq.${adminDetail[1]}&select=*`,
        {
          method: "PATCH",
          headers: { Prefer: "return=representation" },
          body: JSON.stringify(record)
        }
      );

      if (!rows?.length) {
        return response({ error: "Analysis not found." }, 404);
      }

      await saveMediaRecords(adminDetail[1], body.media);

      return response({ analysis: await attachMedia(rows[0]) });
    }

    if (adminDetail && method === "DELETE") {
      await supabase(
        `/rest/v1/analyses?id=eq.${adminDetail[1]}`,
        { method: "DELETE" }
      );

      return response({ ok: true });
    }

    if (method === "POST" && path === "/admin/upload") {
      const authorization = event.headers?.authorization ||
        event.headers?.Authorization || "";

      const token = authorization.startsWith("Bearer ")
        ? authorization.slice(7)
        : "";

      if (!(await verifyToken(token))) {
        return response({ error: "Your session is invalid or expired." }, 401);
      }

      const contentType = event.headers?.["content-type"] ||
        event.headers?.["Content-Type"] || "";

      if (!contentType.toLowerCase().includes("multipart/form-data")) {
        return response({ error: "Upload must use multipart form data." }, 400);
      }

      const rawBody = event.isBase64Encoded
        ? Uint8Array.from(atob(event.body || ""), c => c.charCodeAt(0))
        : new TextEncoder().encode(event.body || "");

      const form = new FormData();
      const boundaryMatch = contentType.match(/boundary=(?:"([^"]+)"|([^;]+))/i);
      const boundary = boundaryMatch?.[1] || boundaryMatch?.[2];

      if (!boundary) {
        return response({ error: "Upload boundary is missing." }, 400);
      }

      const multipartRequest = new Request("https://localhost/upload", {
        method: "POST",
        headers: { "Content-Type": contentType },
        body: rawBody
      });

      const parsedForm = await multipartRequest.formData();
      const file = parsedForm.get("file") || parsedForm.get("image");

      if (!(file instanceof File)) {
        return response({ error: "Choose an image file to upload." }, 400);
      }

      if (!IMAGE_TYPES.has(file.type)) {
        return response({ error: "Only JPG, PNG, and WebP images are allowed." }, 400);
      }

      if (file.size < 1 || file.size > MAX_IMAGE_BYTES) {
        return response({ error: "Images must be no larger than 8 MB." }, 400);
      }

      const extension = ({
        "image/jpeg": "jpg",
        "image/png": "png",
        "image/webp": "webp"
      })[file.type];

      const storagePath =
        `${new Date().toISOString().slice(0, 10)}/${crypto.randomUUID()}.${extension}`;

      const { url, key } = getSupabaseConfig();

      const upload = await fetch(
        `${url}/storage/v1/object/${BUCKET}/${storagePath}`,
        {
          method: "POST",
          headers: {
            apikey: key,
            Authorization: `Bearer ${key}`,
            "Content-Type": file.type,
            "x-upsert": "false"
          },
          body: await file.arrayBuffer()
        }
      );

      if (!upload.ok) {
        const details = await upload.text();
        console.error("Storage upload failed:", upload.status, details);
        throw new Error("Image upload failed. Check the private storage configuration.");
      }

      return response({
        storage_path: storagePath,
        media_type: "image",
        url: await createSignedImageUrl(storagePath)
      }, 201);
    }

    return response({ error: "Route not found." }, 404);
  } catch (error) {
    console.error("API error:", error);

    const status = error.status || 500;
    return response({
      error: status < 500
        ? error.message
        : "The request failed. Check the backend configuration and logs."
    }, status);
  }
}
