
const SUPABASE_URL = (process.env.SUPABASE_URL || "").replace(/\/+$/, "");
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY || "";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const SESSION_SECRET = process.env.SESSION_SECRET || "";

const BUCKET = "analysis-media";
const SESSION_SECONDS = 8 * 60 * 60;
const MAX_IMAGE_BYTES = 8 * 1024 * 1024;
const MAX_TITLE_LENGTH = 180;
const MAX_SUMMARY_LENGTH = 500;
const MAX_CONTENT_LENGTH = 100000;
const MAX_IMAGES = 20;

const ALLOWED_ORIGINS = new Set([
  "https://dreamversehq.com",
  "https://www.dreamversehq.com"
]);

const IMAGE_TYPES = new Map([
  ["image/jpeg", "jpg"],
  ["image/png", "png"],
  ["image/webp", "webp"]
]);

const encoder = new TextEncoder();

function fail(message, status = 400) {
  const error = new Error(message);
  error.status = status;
  return error;
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...headers
    }
  });
}

function getPath(request) {
  const pathname = new URL(request.url).pathname;

  const mediaIndex = pathname.indexOf("/media/");
  if (mediaIndex !== -1) {
    return pathname.slice(mediaIndex);
  }

  const apiIndex = pathname.indexOf("/api/");
  if (apiIndex !== -1) {
    return pathname.slice(apiIndex + 4);
  }

  const functionPrefix = "/.netlify/functions/api";
  const functionIndex = pathname.indexOf(functionPrefix);

  if (functionIndex !== -1) {
    return pathname.slice(functionIndex + functionPrefix.length) || "/";
  }

  return pathname;
}

function corsHeaders(request) {
  const origin = request.headers.get("origin");

  const headers = {
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };

  if (origin && ALLOWED_ORIGINS.has(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
  }

  return headers;
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    throw fail("Request body must contain valid JSON.");
  }
}

function requireConfiguration() {
  if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
    throw fail("Backend database configuration is incomplete.", 500);
  }

  if (
    !ADMIN_PASSWORD ||
    !SESSION_SECRET ||
    SESSION_SECRET.length < 32
  ) {
    throw fail("Backend authentication configuration is incomplete.", 500);
  }
}

/*
 * Supabase secret API keys are supplied using the apikey header.
 * Do not treat the secret API key as a user access token.
 */
function supabaseHeaders(extra = {}) {
  return {
    apikey: SUPABASE_SECRET_KEY,
    ...extra
  };
}

async function db(path, options = {}) {
  requireConfiguration();

  const response = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
    ...options,
    headers: {
      ...supabaseHeaders(),
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });

  const text = await response.text();
  let data = null;

  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }

  if (!response.ok) {
    const message =
      data && typeof data === "object" && data.message
        ? data.message
        : "Database request failed.";

    throw fail(message, response.status >= 500 ? 502 : response.status);
  }

  return data;
}

async function storageRequest(path, options = {}) {
  requireConfiguration();

  const response = await fetch(`${SUPABASE_URL}/storage/v1${path}`, {
    ...options,
    headers: {
      ...supabaseHeaders(),
      ...(options.headers || {})
    }
  });

  const text = await response.text();
  let data = null;

  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }

  if (!response.ok) {
    throw fail(
      data?.message || data?.error || "Image storage request failed.",
      response.status >= 500 ? 502 : response.status
    );
  }

  return data;
}

/* ---------- Admin session security ---------- */

function toBase64Url(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function fromBase64Url(value) {
  const base64 = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padded =
    base64 + "=".repeat((4 - (base64.length % 4)) % 4);

  const binary = atob(padded);

  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

async function hmacSignature(value) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(SESSION_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(value)
  );

  return toBase64Url(new Uint8Array(signature));
}

async function createToken() {
  const payload = toBase64Url(
    encoder.encode(
      JSON.stringify({
        role: "admin",
        expiresAt: Math.floor(Date.now() / 1000) + SESSION_SECONDS
      })
    )
  );

  return `${payload}.${await hmacSignature(payload)}`;
}

function constantTimeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }

  let difference = a.length ^ b.length;
  const length = Math.max(a.length, b.length);

  for (let i = 0; i < length; i++) {
    difference |=
      (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }

  return difference === 0;
}

async function verifyToken(token) {
  if (!token || !SESSION_SECRET || SESSION_SECRET.length < 32) {
    return false;
  }

  const parts = token.split(".");
  if (parts.length !== 2) return false;

  const [payload, signature] = parts;

  try {
    const expected = await hmacSignature(payload);

    if (!constantTimeEqual(signature, expected)) {
      return false;
    }

    const data = JSON.parse(
      new TextDecoder().decode(fromBase64Url(payload))
    );

    return (
      data.role === "admin" &&
      Number(data.expiresAt) > Math.floor(Date.now() / 1000)
    );
  } catch {
    return false;
  }
}

async function requireAdmin(request) {
  const authorization = request.headers.get("authorization") || "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);

  if (!match || !(await verifyToken(match[1]))) {
    throw fail(
      "Your session is invalid or has expired. Please log in again.",
      401
    );
  }
}

/* ---------- Input validation ---------- */

function cleanText(value, maxLength, fieldName, required = false) {
  if (value == null) value = "";

  if (typeof value !== "string") {
    throw fail(`${fieldName} must be text.`);
  }

  const cleaned = value.trim();

  if (required && !cleaned) {
    throw fail(`${fieldName} is required.`);
  }

  if (cleaned.length > maxLength) {
    throw fail(
      `${fieldName} must be ${maxLength} characters or fewer.`
    );
  }

  return cleaned;
}

function cleanAnalysis(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw fail("Invalid analysis data.");
  }

  const title = cleanText(
    body.title,
    MAX_TITLE_LENGTH,
    "Title",
    true
  );

  const summary = cleanText(
    body.summary,
    MAX_SUMMARY_LENGTH,
    "Summary"
  );

  const content = cleanText(
    body.content,
    MAX_CONTENT_LENGTH,
    "Content"
  );

  const market = cleanText(
    body.market ?? body.category ?? "Forex",
    60,
    "Market",
    true
  );

  const status = body.status ?? "draft";

  if (!["draft", "published"].includes(status)) {
    throw fail("Status must be draft or published.");
  }

  const videoUrl = cleanText(
    body.videoUrl ?? body.video_url,
    1000,
    "Video URL"
  );

  if (videoUrl) {
    let parsed;

    try {
      parsed = new URL(videoUrl);
    } catch {
      throw fail("Enter a valid video URL.");
    }

    const host = parsed.hostname.toLowerCase();

    const allowedHosts = new Set([
      "youtube.com",
      "www.youtube.com",
      "m.youtube.com",
      "youtu.be",
      "www.youtu.be",
      "www.youtube-nocookie.com"
    ]);

    if (
      parsed.protocol !== "https:" ||
      !allowedHosts.has(host) ||
      parsed.username ||
      parsed.password
    ) {
      throw fail("Video URL must be a valid YouTube HTTPS link.");
    }
  }

  return {
    title,
    summary,
    content,
    market,
    status,
    video_url: videoUrl || null
  };
}

function cleanImageList(images) {
  if (!Array.isArray(images)) {
    throw fail("Images must be provided as a list.");
  }

  if (images.length > MAX_IMAGES) {
    throw fail(`You can attach up to ${MAX_IMAGES} images per analysis.`);
  }

  const cleaned = images.map((image, index) => {
    if (!image || typeof image !== "object" || Array.isArray(image)) {
      throw fail(`Image ${index + 1} is invalid.`);
    }

    const key = cleanText(image.key, 500, "Image key", true);

    const altText = cleanText(
      image.altText ?? image.alt_text,
      300,
      "Image description"
    );

    if (
      key.startsWith("/") ||
      key.includes("..") ||
      key.includes("\\") ||
      key.includes("?") ||
      key.includes("#") ||
      key.includes("\0")
    ) {
      throw fail(`Image ${index + 1} has an invalid storage key.`);
    }

    return { key, altText };
  });

  const uniqueKeys = new Set(cleaned.map(image => image.key));

  if (uniqueKeys.size !== cleaned.length) {
    throw fail("The same image cannot be added more than once.");
  }

  return cleaned;
}

/* ---------- Private image storage ---------- */

async function signedImageUrl(key) {
  const safeKey = key
    .split("/")
    .map(encodeURIComponent)
    .join("/");

  const result = await storageRequest(
    `/object/sign/${BUCKET}/${safeKey}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ expiresIn: 3600 })
    }
  );

  if (!result?.signedURL) {
    throw fail("Could not create an image link.", 502);
  }

  if (/^https?:\/\//i.test(result.signedURL)) {
    return result.signedURL;
  }

  if (result.signedURL.startsWith("/")) {
    return `${SUPABASE_URL}/storage/v1${result.signedURL}`;
  }

  return `${SUPABASE_URL}/storage/v1/${result.signedURL}`;
}

async function getImages(analysisId) {
  const rows = await db(
    `analysis_media?analysis_id=eq.${encodeURIComponent(analysisId)}` +
    "&select=id,storage_path,media_type,alt_text,sort_order&order=sort_order.asc"
  );

  return (rows || []).map(row => ({
    id: row.id,
    key: row.storage_path,
    altText: row.alt_text || "",
    type: row.media_type,
    url: `/media/${row.storage_path}`
  }));
}

async function isImageLinkedToPublishedAnalysis(key) {
  const mediaRows = await db(
    `analysis_media?storage_path=eq.${encodeURIComponent(key)}` +
    "&select=analysis_id"
  );

  for (const media of mediaRows || []) {
    const rows = await db(
      `analyses?id=eq.${encodeURIComponent(media.analysis_id)}` +
      "&status=eq.published&select=id&limit=1"
    );

    if (rows?.length) return true;
  }

  return false;
}

async function uploadImage(request) {
  const form = await request.formData();
  const file = form.get("file");

  if (!(file instanceof File)) {
    throw fail("Choose an image to upload.");
  }

  if (!IMAGE_TYPES.has(file.type)) {
    throw fail("Only JPG, PNG, and WebP images are allowed.");
  }

  if (file.size <= 0 || file.size > MAX_IMAGE_BYTES) {
    throw fail("Images must be no larger than 8 MB.");
  }

  const extension = IMAGE_TYPES.get(file.type);
  const key = `${crypto.randomUUID()}.${extension}`;

  await storageRequest(`/object/${BUCKET}/${key}`, {
    method: "POST",
    headers: {
      "Content-Type": file.type,
      "x-upsert": "false"
    },
    body: await file.arrayBuffer()
  });

  return { key, altText: "" };
}

/*
 * Remove storage objects only when no analysis_media row still refers to them.
 * Supabase Storage removal uses POST /object/{bucket}, with "prefixes".
 */
async function removeUnusedImages(keys) {
  const candidates = [...new Set(keys.filter(Boolean))];
  const unused = [];

  for (const key of candidates) {
    const references = await db(
      `analysis_media?storage_path=eq.${encodeURIComponent(key)}&select=id&limit=1`
    );

    if (!references?.length) {
      unused.push(key);
    }
  }

  if (!unused.length) return;

  await storageRequest(`/object/${BUCKET}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ prefixes: unused })
  });
}

/*
 * Replace image associations once.
 * The caller must send "images" explicitly to replace or clear the list.
 */
async function saveImages(analysisId, images) {
  const cleanImages = cleanImageList(images);

  const existing = await db(
    `analysis_media?analysis_id=eq.${encodeURIComponent(analysisId)}` +
    "&select=storage_path"
  );

  const oldKeys = (existing || []).map(item => item.storage_path);

  await db(
    `analysis_media?analysis_id=eq.${encodeURIComponent(analysisId)}`,
    {
      method: "DELETE",
      headers: { Prefer: "return=minimal" }
    }
  );

  if (cleanImages.length) {
    const rows = cleanImages.map((image, index) => ({
      analysis_id: analysisId,
      storage_path: image.key,
      media_type: "image",
      alt_text: image.altText,
      sort_order: index
    }));

    await db("analysis_media", {
      method: "POST",
      headers: { Prefer: "return=minimal" },
      body: JSON.stringify(rows)
    });
  }

  const retainedKeys = new Set(cleanImages.map(image => image.key));
  const keysToCheck = oldKeys.filter(key => !retainedKeys.has(key));

  if (keysToCheck.length) {
    try {
      await removeUnusedImages(keysToCheck);
    } catch {
      // A failed cleanup must not undo a successful analysis save.
      // Unused files can be cleaned up later.
    }
  }
}

/* ---------- Analysis database helpers ---------- */

function publicAnalysis(row, images = []) {
  return {
    id: row.id,
    title: row.title,
    summary: row.summary || "",
    content: row.content || "",
    category: row.market || "Forex",
    market: row.market || "Forex",
    status: row.status,
    videoUrl: row.video_url || "",
    images,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    publishedAt: row.published_at
  };
}

async function getPublishedAnalysis(id) {
  const rows = await db(
    `analyses?id=eq.${encodeURIComponent(id)}` +
    "&status=eq.published&select=*&limit=1"
  );

  return rows?.[0] || null;
}

async function getAnalysisForAdmin(id) {
  const rows = await db(
    `analyses?id=eq.${encodeURIComponent(id)}&select=*&limit=1`
  );

  return rows?.[0] || null;
}

async function listAnalyses(isAdmin) {
  const filter = isAdmin ? "" : "&status=eq.published";

  const rows = await db(
    `analyses?select=*&order=published_at.desc.nullslast,created_at.desc${filter}`
  );

  return Promise.all(
    (rows || []).map(async row => {
      return publicAnalysis(row, await getImages(row.id));
    })
  );
}

/* ---------- Analysis deletion ---------- */

async function deleteAnalysis(id) {
  const existing = await getAnalysisForAdmin(id);

  if (!existing) {
    throw fail("Analysis not found.", 404);
  }

  const media = await db(
    `analysis_media?analysis_id=eq.${encodeURIComponent(id)}` +
    "&select=storage_path"
  );

  const keys = (media || [])
    .map(item => item.storage_path)
    .filter(Boolean);

  // Deleting the analysis cascades to its analysis_media rows.
  await db(
    `analyses?id=eq.${encodeURIComponent(id)}`,
    {
      method: "DELETE",
      headers: { Prefer: "return=minimal" }
    }
  );

  try {
    await removeUnusedImages(keys);
  } catch {
    // Database deletion succeeded. Storage cleanup can be retried later.
  }

  return { ok: true };
}

/* ---------- API routes ---------- */

async function handle(request, path) {
  const method = request.method.toUpperCase();

  if (method === "GET" && path === "/health") {
    return {
      ok: true,
      service: "dreamverse-market-analysis-api",
      message: "Backend is running."
    };
  }

  if (method === "POST" && path === "/admin/login") {
    requireConfiguration();

    const body = await readJson(request);
    const password =
      typeof body.password === "string" ? body.password : "";

    if (!constantTimeEqual(password, ADMIN_PASSWORD)) {
      throw fail("Incorrect password.", 401);
    }

    return { token: await createToken() };
  }

  if (method === "GET" && path === "/analyses") {
    return { analyses: await listAnalyses(false) };
  }

  const publicDetail = path.match(/^\/analyses\/([^/]+)$/);

  if (method === "GET" && publicDetail) {
    let id;

    try {
      id = decodeURIComponent(publicDetail[1]);
    } catch {
      throw fail("Invalid analysis ID.");
    }

    const row = await getPublishedAnalysis(id);

    if (!row) {
      throw fail("Analysis not found.", 404);
    }

    return publicAnalysis(row, await getImages(row.id));
  }

  if (path.startsWith("/admin/")) {
    await requireAdmin(request);
  }

  if (method === "GET" && path === "/admin/analyses") {
    return { analyses: await listAnalyses(true) };
  }

  if (method === "POST" && path === "/admin/upload") {
    return await uploadImage(request);
  }

  if (method === "POST" && path === "/admin/analyses") {
    const body = await readJson(request);
    const analysis = cleanAnalysis(body);
    const now = new Date().toISOString();

    const inserted = await db("analyses?select=*", {
      method: "POST",
      headers: { Prefer: "return=representation" },
      body: JSON.stringify({
        ...analysis,
        created_at: now,
        updated_at: now,
        published_at:
          analysis.status === "published" ? now : null
      })
    });

    const row = inserted?.[0];

    if (!row) {
      throw fail("Could not create the analysis.", 500);
    }

    if (Object.prototype.hasOwnProperty.call(body, "images")) {
      await saveImages(row.id, body.images);
    }

    return publicAnalysis(row, await getImages(row.id));
  }

  const adminDetail = path.match(/^\/admin\/analyses\/([^/]+)$/);

  if (adminDetail && method === "PUT") {
    let id;

    try {
      id = decodeURIComponent(adminDetail[1]);
    } catch {
      throw fail("Invalid analysis ID.");
    }

    const body = await readJson(request);
    const existing = await getAnalysisForAdmin(id);

    if (!existing) {
      throw fail("Analysis not found.", 404);
    }

    const analysis = cleanAnalysis(body);
    const now = new Date().toISOString();

    let publishedAt = existing.published_at;

    if (analysis.status === "draft") {
      publishedAt = null;
    } else if (existing.status !== "published" || !publishedAt) {
      publishedAt = now;
    }

    const updated = await db(
      `analyses?id=eq.${encodeURIComponent(id)}&select=*`,
      {
        method: "PATCH",
        headers: { Prefer: "return=representation" },
        body: JSON.stringify({
          ...analysis,
          updated_at: now,
          published_at: publishedAt
        })
      }
    );

    const row = updated?.[0];

    if (!row) {
      throw fail("Could not update the analysis.", 500);
    }

    // Omitted "images" means keep existing images.
    // An explicit empty array means remove all images.
    if (Object.prototype.hasOwnProperty.call(body, "images")) {
      await saveImages(row.id, body.images);
    }

    return publicAnalysis(row, await getImages(row.id));
  }

  if (adminDetail && method === "DELETE") {
    let id;

    try {
      id = decodeURIComponent(adminDetail[1]);
    } catch {
      throw fail("Invalid analysis ID.");
    }

    return await deleteAnalysis(id);
  }

  const mediaMatch = path.match(/^\/media\/(.+)$/);

  if (method === "GET" && mediaMatch) {
    let key;

    try {
      key = decodeURIComponent(mediaMatch[1]);
    } catch {
      throw fail("Invalid image path.");
    }

    if (
      !key ||
      key.startsWith("/") ||
      key.includes("..") ||
      key.includes("\\") ||
      key.includes("?") ||
      key.includes("#") ||
      key.includes("\0")
    ) {
      throw fail("Invalid image path.");
    }

    if (!(await isImageLinkedToPublishedAnalysis(key))) {
      throw fail("Image not found.", 404);
    }

    return { redirectTo: await signedImageUrl(key) };
  }

  throw fail("Route not found.", 404);
}

/* ---------- Netlify function entry point ---------- */

export default async function handler(request) {
  const headers = corsHeaders(request);
  const origin = request.headers.get("origin");

  if (origin && !ALLOWED_ORIGINS.has(origin)) {
    return json({ error: "Origin not allowed." }, 403, headers);
  }

  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers
    });
  }

  try {
    const path = getPath(request);
    const data = await handle(request, path);

    if (request.method === "GET" && path.startsWith("/media/")) {
      return new Response(null, {
        status: 302,
        headers: {
          ...headers,
          Location: data.redirectTo,
          "Cache-Control": "private, no-store"
        }
      });
    }

    return json(data, 200, headers);
  } catch (error) {
    const status = Number.isInteger(error.status)
      ? error.status
      : 500;

    if (status >= 500) {
      // Avoid exposing internal error details to visitors.
      return json(
        { error: "A server error occurred. Please try again." },
        status,
        headers
      );
    }

    return json(
      { error: error.message || "Request failed." },
      status,
      headers
    );
  }
}
  
