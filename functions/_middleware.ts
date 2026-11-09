/**
 * 全站访问控制中间件
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

export const onRequest: PagesFunction<Env> = async (context) => {
	const url = new URL(context.request.url);
	const path = url.pathname;

	if (isPublic(path)) {
		return context.next();
	}

	const user = await currentUser(context.env, context.request);
	if (user) {
		return context.next();
	}

	// API 请求返回 401，页面请求跳登录
	if (path.startsWith("/api/")) {
		return new Response(JSON.stringify({ error: "未登录" }), {
			status: 401,
			headers: { "Content-Type": "application/json; charset=utf-8" },
		});
	}

	const target = "/login?next=" + encodeURIComponent(path + url.search);
	return new Response(null, {
		status: 302,
		headers: { Location: target, "Cache-Control": "no-store" },
	});
};
