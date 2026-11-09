/**
 * 认证工具：PBKDF2 密码哈希 + HMAC 签名会话 cookie
 * 运行在 Cloudflare Pages Functions（Workers 运行时）
 */

export interface Env {
	DB: D1Database;
	AUTH_SECRET: string;
}

const COOKIE = "ff_auth";
const SESSION_DAYS = 7;
const PBKDF2_ITER = 120000;

const enc = new TextEncoder();

function b64(bytes: ArrayBuffer | Uint8Array): string {
	const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
	let s = "";
	for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
	return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function unb64(str: string): Uint8Array {
	const s = str.replace(/-/g, "+").replace(/_/g, "/");
	const pad = s.length % 4 ? "=".repeat(4 - (s.length % 4)) : "";
	const bin = atob(s + pad);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

export async function hashPassword(password: string): Promise<string> {
	const salt = crypto.getRandomValues(new Uint8Array(16));
	const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
	const bits = await crypto.subtle.deriveBits(
		{ name: "PBKDF2", salt, iterations: PBKDF2_ITER, hash: "SHA-256" },
		key,
		256,
	);
	return `pbkdf2$${PBKDF2_ITER}$${b64(salt)}$${b64(bits)}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
	const parts = (stored || "").split("$");
	if (parts.length !== 4) return false;
	const iter = parseInt(parts[1], 10);
	const salt = unb64(parts[2]);
	const expect = unb64(parts[3]);
	const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
	const bits = new Uint8Array(
		await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" }, key, 256),
	);
	if (bits.length !== expect.length) return false;
	let diff = 0;
	for (let i = 0; i < bits.length; i++) diff |= bits[i] ^ expect[i];
	return diff === 0;
}

async function hmac(secret: string, data: string): Promise<string> {
	const key = await crypto.subtle.importKey(
		"raw",
		enc.encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
	return b64(sig);
}

export async function makeSessionToken(env: Env, userId: number): Promise<{ token: string; expires: number }> {
	const expires = Date.now() + SESSION_DAYS * 86400000;
	const rand = b64(crypto.getRandomValues(new Uint8Array(16)));
	const payload = `${userId}.${expires}.${rand}`;
	const sig = await hmac(env.AUTH_SECRET || "dev-secret", payload);
	return { token: `${payload}.${sig}`, expires };
}

export async function readSession(env: Env, token: string): Promise<{ userId: number } | null> {
	const parts = (token || "").split(".");
	if (parts.length !== 4) return null;
	const [idStr, expStr, rand, sig] = parts;
	const payload = `${idStr}.${expStr}.${rand}`;
	const expect = await hmac(env.AUTH_SECRET || "dev-secret", payload);
	if (sig !== expect) return null;
	const userId = parseInt(idStr, 10);
	const expires = parseInt(expStr, 10);
	if (!userId || !expires || expires < Date.now()) return null;
	return { userId };
}

export function sessionCookie(token: string, maxAgeSec: number): string {
	return `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSec}`;
}

export function clearCookie(): string {
	return `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

export function getCookie(request: Request, name = COOKIE): string | null {
	const raw = request.headers.get("Cookie") || "";
	for (const part of raw.split(";")) {
		const [k, ...v] = part.trim().split("=");
		if (k === name) return v.join("=");
	}
	return null;
}

export interface UserRow {
	id: number;
	name: string;
	role: string;
	status: string;
	created_at: number;
	last_login: number | null;
	last_login_ip?: string;
	last_ip: string | null;
	last_ua: string | null;
	login_count: number;
}

export async function currentUser(env: Env, request: Request): Promise<UserRow | null> {
	const token = getCookie(request);
	if (!token) return null;
	const sess = await readSession(env, token);
	if (!sess) return null;
	const row = await env.DB.prepare(
		"SELECT id, name, role, status, created_at, last_login, last_ip, last_ua, login_count FROM users WHERE id = ?",
	)
		.bind(sess.userId)
		.first<UserRow>();
	if (!row || row.status !== "active") return null;
	return row;
}

export async function requireAdmin(env: Env, request: Request): Promise<UserRow | null> {
	const u = await currentUser(env, request);
	if (!u || u.role !== "admin") return null;
	return u;
}

export function json(data: unknown, status = 200, headers: Record<string, string> = {}): Response {
	return new Response(JSON.stringify(data), {
		status,
		headers: {
			"Content-Type": "application/json; charset=utf-8",
			"Cache-Control": "no-store",
			...headers,
		},
	});
}

export function clientInfo(request: Request) {
	const ip =
		request.headers.get("CF-Connecting-IP") ||
		request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() ||
		"unknown";
	const ua = request.headers.get("User-Agent") || "unknown";
	return { ip, ua: ua.slice(0, 300) };
}

export async function getSetting(env: Env, key: string): Promise<string | null> {
	const row = await env.DB.prepare("SELECT value FROM settings WHERE key = ?").bind(key).first<{ value: string }>();
	return row ? row.value : null;
}

export async function setSetting(env: Env, key: string, value: string): Promise<void> {
	await env.DB.prepare(
		"INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
	)
		.bind(key, value)
		.run();
}

export function cleanName(name: string): string {
	return (name || "").trim().replace(/[^\u4e00-\u9fa5A-Za-z0-9_-]/g, "").slice(0, 20);
}
