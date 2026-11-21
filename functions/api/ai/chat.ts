/**
 * AI 对话接口 —— 仅管理员可用
 *
 * 挂载路径：/api/ai/chat
 * 鉴权：复用现有 cookie 会话，且必须是 admin 角色
 * 后端：直连 DeepSeek API（公网站点无法访问本地网关）
 *
 * 部署前需要在 Cloudflare Pages 里配置环境变量：
 *   DEEPSEEK_API_KEY = sk-xxxx
 */
import { json, requireAdmin, type Env } from "../../_lib/auth";

interface AIEnv extends Env {
	DEEPSEEK_API_KEY: string;
}

const ALLOWED_MODELS = new Set(["deepseek-v4-pro", "deepseek-flash"]);

export const onRequestPost: PagesFunction<AIEnv> = async (ctx) => {
	// ---- 1. 鉴权：必须是管理员 ----
	const user = await requireAdmin(ctx.env, ctx.request);
	if (!user) {
		return json({ error: "仅管理员可用" }, 403);
	}

	// ---- 2. 取 key ----
	const key = ctx.env.DEEPSEEK_API_KEY;
	if (!key) {
		return json({ error: "服务端未配置 DEEPSEEK_API_KEY" }, 500);
	}

	// ---- 3. 校验入参 ----
	let body: any;
	try {
		body = await ctx.request.json();
	} catch {
		return json({ error: "请求体不是合法 JSON" }, 400);
	}

	const messages = Array.isArray(body?.messages) ? body.messages : [];
	if (!messages.length) return json({ error: "缺少 messages" }, 400);
	if (messages.length > 40) return json({ error: "对话过长，请清空重开" }, 400);

	// 只保留 role/content，防止前端塞奇怪字段进来
	const clean = messages
		.filter((m: any) => m && (m.role === "user" || m.role === "assistant"))
		.map((m: any) => ({ role: m.role, content: String(m.content ?? "").slice(0, 60000) }))
		.filter((m: any) => m.content.length > 0);
	if (!clean.length) return json({ error: "没有有效内容" }, 400);

	const model = ALLOWED_MODELS.has(body?.model) ? body.model : "deepseek-v4-pro";
	const maxTokens = Math.min(Math.max(parseInt(body?.max_tokens, 10) || 2048, 64), 8192);

	// ---- 4. 转发到 DeepSeek（流式）----
	let upstream: Response;
	try {
		upstream = await fetch("https://api.deepseek.com/v1/chat/completions", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Authorization: `Bearer ${key}`,
			},
			body: JSON.stringify({
				model,
				messages: clean,
				stream: true,
				max_tokens: maxTokens,
			}),
		});
	} catch (e: any) {
		return json({ error: `无法连接上游：${e?.message || e}` }, 502);
	}

	if (!upstream.ok || !upstream.body) {
		const detail = await upstream.text().catch(() => "");
		return json({ error: `上游返回 ${upstream.status}`, detail: detail.slice(0, 400) }, 502);
	}

	// ---- 5. 原样流式回给浏览器 ----
	return new Response(upstream.body, {
		headers: {
			"Content-Type": "text/event-stream; charset=utf-8",
			"Cache-Control": "no-cache, no-transform",
			"X-Accel-Buffering": "no",
		},
	});
};

/** 用一个 GET 让前端能探测「这个功能是否可用」 */
export const onRequestGet: PagesFunction<AIEnv> = async (ctx) => {
	const user = await requireAdmin(ctx.env, ctx.request);
	if (!user) return json({ ok: false, error: "仅管理员可用" }, 403);
	return json({
		ok: true,
		configured: Boolean(ctx.env.DEEPSEEK_API_KEY),
		models: [...ALLOWED_MODELS],
		user: user.name,
	});
};
