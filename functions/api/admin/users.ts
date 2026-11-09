import { json, requireAdmin, type Env } from "../../_lib/auth";

export const onRequestGet: PagesFunction<Env> = async (context) => {
	const admin = await requireAdmin(context.env, context.request);
	if (!admin) return json({ error: "没有权限" }, 403);

	const rows = await context.env.DB.prepare(
		`SELECT id, name, role, status, created_at, last_login, last_ip, last_ua, login_count
		 FROM users ORDER BY id ASC`,
	).all();

	return json({ users: rows.results || [], me: admin.name });
};
