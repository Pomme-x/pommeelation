import { json, requireAdmin, setSetting, getSetting, type Env } from "../../_lib/auth";

export const onRequestGet: PagesFunction<Env> = async (context) => {
	const admin = await requireAdmin(context.env, context.request);
	if (!admin) return json({ error: "没有权限" }, 403);
	return json({
		max_users: await getSetting(context.env, "max_users"),
		register_code: await getSetting(context.env, "register_code"),
	});
};

export const onRequestPost: PagesFunction<Env> = async (context) => {
	const admin = await requireAdmin(context.env, context.request);
	if (!admin) return json({ error: "没有权限" }, 403);

	let body: any;
	try {
		body = await context.request.json();
	} catch {
		return json({ error: "请求格式错误" }, 400);
	}

	if (body.max_users !== undefined) {
		const n = parseInt(String(body.max_users), 10);
		if (!n || n < 1 || n > 999) return json({ error: "名额要在 1-999 之间" }, 400);
		await setSetting(context.env, "max_users", String(n));
	}
	if (body.register_code !== undefined) {
		const code = String(body.register_code).slice(0, 40);
		await setSetting(context.env, "register_code", code);
	}
	return json({ ok: true });
};
