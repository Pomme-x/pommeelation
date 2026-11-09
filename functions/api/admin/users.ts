import { json, requireAdmin, type Env } from "../../_lib/auth";

export const onRequestGet: PagesFunction<Env> = async (context) => {
	const admin = await requireAdmin(context.env, context.request);
	if (!admin) return json({ error: "没有权限" }, 403);

	const rows = await context.env.DB.prepare(
		`SELECT id, name, role, status, created_at, last_login, last_ip, last_ua, login_count,
		        failed_count, locked_until
		 FROM users ORDER BY id ASC`,
	).all();

	const logs = await context.env.DB.prepare(
		`SELECT user_id, name, ip, ua, at, ok FROM login_logs ORDER BY at DESC LIMIT 600`,
	).all();

	const online = await context.env.DB.prepare(
		"SELECT COUNT(DISTINCT user_id) AS n FROM sessions WHERE expires_at > ?",
	)
		.bind(Date.now())
		.first<{ n: number }>();

	return json({
		users: rows.results || [],
		logs: logs.results || [],
		me: admin.name,
		online: online?.n || 0,
	});
};
