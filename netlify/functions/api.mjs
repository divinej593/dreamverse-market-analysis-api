
const ALLOWED_ORIGINS = new Set([
  "https://dreamversehq.com",
  "https://www.dreamversehq.com"
]);

const MAX_IMAGE_BYTES = 8 * 1024 * 1024;
const MAX_TITLE_LENGTH = 180;
const MAX_SUMMARY_LENGTH = 500;
const SESSION_SECONDS = 8 * 60 * 60;
const BUCKET = "analysis-media";

const IMAGE_TYPES = new Set([
  "image/jpeg",
  "image/png",
  "image/webp"
]);

function response(data, status = 200, origin = "") {
  const headers = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
    "Vary": "Origin",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS"
  };

  if (ALLOWED_ORIGINS.has(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
  }

  return new Response(JSON.stringify(data), { status, headers });
}

function getMethod(event) {
  return (
    event.httpMethod ||
    event.requestContext?.http?.method ||
    "GET"
  ).toUpperCase();
}

function getPath(event) {
  const paths = [
    event.path,
    new URL(event.rawUrl || "https://localhost").pathname
  ];

  for (let path of paths) {
    if (!path) continue;

    path = path.replace(/\/+$/, "") || "/";

    const marker = "/.netlify/functions/api";
    const index = path.indexOf(marker);

    if (index !== -1) {
      return path.slice(index + marker.length) || "/";
    }

    const apiIndex = path.indexOf("/api/");
    if (apiIndex !== -1) return path.slice(apiIndex + 4);

    if (path === "/api") return "/";
  }

  return "/";
}

function fail(message, status = 400) {
  return Object.assign(new Error(message), { status });
}

function parseBody(event) {
  if (!event.body) return {};

  try {
    const body = event.isBase64Encoded
      ? atob(event.body)
      : event.body;

    return JSON.parse(body);
  } catch {
    throw fail("Invalid JSON request body.");
  }
}

function config() {
  const url = process.env.SUPABASE_URL?.replace(/\/+$/, "");
  const key = process.env.SUPABASE_SECRET_KEY;

  if (!url || !key) {
    throw new Error("Supabase environment variables are missing.");
  }

  return { url, key };
}

async function db(path, options = {}) {
  const { url, key } = config();

  const headers = {
    apikey: key,
    Authorization: `Bearer ${key}`,
    ...options.headers
  };

  if (options.body && !(options.body instanceof ArrayBuffer)) {
    headers["Content-Type"] ||= "application/json";
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
    console.error("Supabase error:", result.status, data);
    throw new Error(`Database or storage request failed (${result.status}).`);
  }

  return data;
}

function encodeBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function makeToken() {
  const secret = process.env.SESSION_SECRET;

  if (!secret || secret.length < 32) {
    throw new Error("SESSION_SECRET must contain at least 32 characters.");
  }

  const payload = encodeBase64Url(
    new TextEncoder().encode(JSON.stringify({
      role: "admin",
      exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS
    }))
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
    new TextEncoder().encode(payload)
  );

  return `${payload}.${encodeBase64Url(new Uint8Array(signature))}`;
}

async function isValidToken(token) {
  const secret = process.env.SESSION_SECRET;
  if (!secret || !token) return false;

  const parts = token.split(".");
  if (parts.length !== 2) return false;

  try {
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const signatureText = parts[1]
      .replace(/-/g, "+")
      .replace(/_/g, "/");

    const signature = Uint8Array.from(
      atob(signatureText + "=".repeat((4 - signatureText.length % 4) % 4)),
      character => character.charCodeAt(0)
    );

    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      signature,
      new TextEncoder().encode(parts[0])
    );

    if (!valid) return false;

    const payloadText = parts[0]
      .replace(/-/g, "+")
      .replace(/_/g, "/");

    const payload = JSON.parse(
      atob(payloadText + "=".repeat((4 - payloadText.length % 4) % 4))
    );

    return payload.role === "admin" &&
      payload.exp > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

async function authorize(event) {
  const headers = event.headers || {};
  const authorization = headers.authorization || headers.Authorization || "";
  const token = authorization.startsWith("Bearer ")
    ? authorization.slice(7)
    : "";

  if (!(await isValidToken(token))) {
    throw fail("Your session is invalid or expired. Please log in again.", 401);
  }
}

function validVideoUrl(value) {
  if (!value) return null;

  try {
    const url = new URL(value);
    const allowedHosts = new Set([
      "youtube.com",
      "www.youtube.com",
      "m.youtube.com",
      "youtu.be",
      "www.youtube-nocookie.com"
    ]);

    if (url.protocol !== "https:" || !allowedHosts.has(url.hostname.toLowerCase())) {
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
  const category = String(body.category || "Other").trim();
  const videoUrl = validVideoUrl(body.videoUrl ?? body.video_url ?? "");
  const status = body.status === "published" ? "published" : "draft";

  if (!title || title.length > MAX_TITLE_LENGTH) {
    throw fail("Title is required and must be 180 characters or fewer.");
  }

  if (summary.length > MAX_SUMMARY_LENGTH) {
    throw fail("Summary must be 500 characters or fewer.");
  }

  if (content.length > 100000) {
    throw fail("Analysis content is too long.");
  }

  if (videoUrl === false) {
    throw fail("Use a valid HTTPS YouTube video link.");
  }

  if (!category || category.length > 100) {
    throw fail("A valid category is required.");
  }

  const record = {
    title,
    summary,
    content,
    market: category,
    status,
    video_url: videoUrl,
    updated_at: new Date().toISOString()
  };

  if (status === "published") {
    record.published_at = new Date().toISOString();
  }

  return record;
}

function mapAnalysis(row, images = []) {
  return {
    ...row,
    category: row.market || "Other",
    videoUrl: row.video_url || "",
    images
  };
}

async function signedImageUrl(key) {
  const safePath = String(key).split("/").map(encodeURIComponent).join("/");

  const result = await db(
    `/storage/v1/object/sign/${BUCKET}/${safePath}`,
    {
      method: "POST",
      body: JSON.stringify({ expiresIn: 3600 })
    }
  );

  const signed = result?.signedURL || result?.signedUrl;
  if (!signed) return null;

  const { url } = config();

  return signed.startsWith("http")
    ? signed
    : `${url}/storage/v1${signed.startsWith("/") ? "" : "/"}${signed}`;
}

async function getImages(analysisId) {
  const rows = await db(
    `/rest/v1/analysis_media?analysis_id=eq.${analysisId}&select=id,storage_path,alt_text,sort_order&order=sort_order.asc`
  );

  return Promise.all((rows || []).map(async row => ({
    id: row.id,
    key: row.storage_path,
    altText: row.alt_text || "",
    order: row.sort_order,
    url: await signedImageUrl(row.storage_path)
  })));
}

async function withImages(row) {
  return mapAnalysis(row, await getImages(row.id));
}

async function saveImages(analysisId, images) {
  if (!Array.isArray(images)) return;

  if (images.length > 20) {
    throw fail("An analysis can contain at most 20 images.");
  }

  for (const image of images) {
    if (!image || typeof image.key !== "string") {
      throw fail("An image entry is missing its storage key.");
    }
  }

  await db(
    `/rest/v1/analysis_media?analysis_id=eq.${analysisId}`,
    { method: "DELETE" }
  );

  const rows = images.map((image, index) => ({
    analysis_id: analysisId,
    storage_path: image.key,
    media_type: "image",
    alt_text: String(image.altText || "").slice(0, 300),
    sort_order: Number.isInteger(image.order) ? image.order : index
  }));

  if (rows.length) {
    await db("/rest/v1/analysis_media", {
      method: "POST",
      headers: { Prefer: "return=minimal" },
      body: JSON.stringify(rows)
    });
  }
}

async function removeStoredImage(key) {
  const safePath = String(key).split("/").map(encodeURIComponent).join("/");

  await db(`/storage/v1/object/${BUCKET}/${safePath}`, {
    method: "DELETE"
  });
}

async function handle(event, path, method) {
  if (method === "GET" && path === "/health") {
    return {
      ok: true,
      service: "dreamverse-market-analysis-api"
    };
  }

  if (method === "POST" && path === "/admin/login") {
    const body = parseBody(event);
    const password = process.env.ADMIN_PASSWORD;

    if (!password) {
      throw new Error("ADMIN_PASSWORD is not configured.");
    }

    if (typeof body.password !== "string" || body.password !== password) {
      throw fail("Incorrect password.", 401);
    }

    return {
      token: await makeToken(),
      expiresIn: SESSION_SECONDS
    };
  }

  if (method === "GET" && path === "/analyses") {
    const rows = await db(
      "/rest/v1/analyses?status=eq.published&select=*&order=published_at.desc.nullslast,created_at.desc"
    );

    return {
      analyses: await Promise.all((rows || []).map(withImages))
    };
  }

  const publicDetail = path.match(/^\/analyses\/([0-9a-f-]{36})$/i);

  if (method === "GET" && publicDetail) {
    const rows = await db(
      `/rest/v1/analyses?id=eq.${publicDetail[1]}&status=eq.published&select=*`
    );

    if (!rows?.length) throw fail("Analysis not found.", 404);

    return { analysis: await withImages(rows[0]) };
  }

  if (path.startsWith("/admin/")) {
    await authorize(event);
  }

  if (method === "GET" && path === "/admin/analyses") {
    const rows = await db(
      "/rest/v1/analyses?select=*&order=created_at.desc"
    );

    return {
      analyses: await Promise.all((rows || []).map(withImages))
    };
  }

  if (method === "POST" && path === "/admin/analyses") {
    const body = parseBody(event);
    const record = cleanAnalysis(body);

    const rows = await db("/rest/v1/analyses", {
      method: "POST",
      headers: { Prefer: "return=representation" },
      body: JSON.stringify(record)
    });

    if (!rows?.length) throw new Error("Analysis could not be created.");

    await saveImages(rows[0].id, body.images || []);

    return { analysis: await withImages(rows[0]) };
  }

  const adminDetail = path.match(/^\/admin\/analyses\/([0-9a-f-]{36})$/i);

  if (adminDetail && method === "PUT") {
    const body = parseBody(event);
    const record = cleanAnalysis(body);

    const rows = await db(
      `/rest/v1/analyses?id=eq.${adminDetail[1]}&select=*`,
      {
        method: "PATCH",
        headers: { Prefer: "return=representation" },
        body: JSON.stringify(record)
      }
    );

    if (!rows?.length) throw fail("Analysis not found.", 404);

    await saveImages(adminDetail[1], body.images || []);

    return { analysis: await withImages(rows[0]) };
  }

  if (adminDetail && method === "DELETE") {
    const images = await db(
      `/rest/v1/analysis_media?analysis_id=eq.${adminDetail[1]}&select=storage_path`
    );

    for (const image of images || []) {
      try {
        await removeStoredImage(image.storage_path);
      } catch (error) {
        console.error("Image cleanup warning:", error);
      }
    }

    await db(`/rest/v1/analyses?id=eq.${adminDetail[1]}`, {
      method: "DELETE"
    });

    return { ok: true };
  }

  if (method === "POST" && path === "/admin/upload") {
    const headers = event.headers || {};
    const contentType = headers["content-type"] || headers["Content-Type"] || "";

    if (!contentType.toLowerCase().includes("multipart/form-data")) {
      throw fail("Upload must use multipart form data.");
    }

    const rawBody = event.isBase64Encoded
      ? Uint8Array.from(atob(event.body || ""), c => c.charCodeAt(0))
      : new TextEncoder().encode(event.body || "");

    const request = new Request("https://localhost/upload", {
      method: "POST",
      headers: { "Content-Type": contentType },
      body: rawBody
    });

    const form = await request.formData();
    const file = form.get("file");

    if (!(file instanceof File)) {
      throw fail("Choose an image file to upload.");
    }

    if (!IMAGE_TYPES.has(file.type)) {
      throw fail("Only JPG, PNG, and WebP images are allowed.");
    }

    if (file.size < 1 || file.size > MAX_IMAGE_BYTES) {
      throw fail("Images must be no larger than 8 MB.");
    }

    const extension = {
      "image/jpeg": "jpg",
      "image/png": "png",
      "image/webp": "webp"
    }[file.type];

    const key = `${new Date().toISOString().slice(0, 10)}/${crypto.randomUUID()}.${extension}`;
    const { url, key: secret } = config();

    const upload = await fetch(
      `${url}/storage/v1/object/${BUCKET}/${key}`,
      {
        method: "POST",
        headers: {
          apikey: secret,
          Authorization: `Bearer ${secret}`,
          "Content-Type": file.type,
          "x-upsert": "false"
        },
        body: await file.arrayBuffer()
      }
    );

    if (!upload.ok) {
      console.error("Storage upload failed:", upload.status, await upload.text());
      throw new Error("Image upload failed. Check Supabase storage settings.");
    }

    return { key, altText: "" };
  }

  const adminMedia = path.match(/^\/admin\/media\/(.+)$/);

  if (method === "GET" && adminMedia) {
    const key = decodeURIComponent(adminMedia[1]);
    return { url: await signedImageUrl(key) };
  }

  throw fail("Route not found.", 404);
}

export default async function handler(event) {
  const method = getMethod(event);
  const origin = event.headers?.origin || event.headers?.Origin || "";
  const path = getPath(event);

  if (method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": ALLOWED_ORIGINS.has(origin) ? origin : "null",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Vary": "Origin"
      }
    });
  }

  if (origin && !ALLOWED_ORIGINS.has(origin)) {
    return response({ error: "Origin not allowed." }, 403, origin);
  }

  try {
    const data = await handle(event, path, method);
    return response(data, method === "POST" && path === "/admin/upload" ? 201 : 200, origin);
  } catch (error) {
    console.error("API error:", error);

    const status = error.status || 500;
    const message = status < 500
      ? error.message
      : "The request failed. Check the backend configuration and logs.";

    return response({ error: message }, status, origin);
  }
    }
