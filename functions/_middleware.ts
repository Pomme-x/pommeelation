/**
 * 全站访问控制中间件 + 安全响应头
 * 未登录访客只能看到 /login /register 和静态资源
 */
import { currentUser, type Env } from "./_lib/auth";

const PUBLIC_PREFIXES = [
	"/login",
	"/register",
	"/api/auth/",
	"/_astro/",
	"/_image",
	"/favicon",
	"/assets/",
	"/gallery/",
	"/images/",
	"/pagefind/",
	"/rss",
	"/atom",
	"/sitemap",
	"/robots.txt",
	"/llms.txt",
];

function isPublic(pathname: string): boolean {
	return PUBLIC_PREFIXES.some((p) => pathname === p || pathname.startsWith(p));
}

function harden(res: Response): Response {
	const h = new Headers(res.headers);
	h.set("X-Content-Type-Options", "nosniff");
	h.set("X-Frame-Options", "SAMEORIGIN");
	h.set("Referrer-Policy", "strict-origin-when-cross-origin");
	h.set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()");
	h.set("Cross-Origin-Opener-Policy", "same-origin");
	if (!h.has("Cache-Control") && res.status !== 200) h.set("Cache-Control", "no-store");
	return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h });
}

export const onRequest: PagesFunction<Env> = async (context) => {
	const url = new URL(context.request.url);
	const base = url.pathname.startsWith("/pommeelation") ? "/pommeelation" : "";
	const path = url.pathname.slice(base.length) || "/";

	if (isPublic(path)) {
		return harden(await context.next());
	}

	const user = await currentUser(context.env, context.request);
	if (user) {
		return harden(await context.next());
	}

	if (path.startsWith("/api/")) {
		return new Response(JSON.stringify({ error: "未登录" }), {
			status: 401,
			headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
		});
	}

	const target = base + "/login?next=" + encodeURIComponent(path + url.search);
	return new Response(null, {
		status: 302,
		headers: { Location: target, "Cache-Control": "no-store" },
	});
};
