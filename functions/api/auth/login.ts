import {
	cleanName,
	clientInfo,
	json,
	makeSessionToken,
	sessionCookie,
	verifyPassword,
	type Env,
} from "../../_lib/auth";

export const onRequestPost: PagesFunction<Env> = async (context) => {
	const { request, env } = context;

	let body: any;
	try {
		body = await request.json();
	} catch {
		return json({ error: "请求格式错误" }, 400);
	}

	const name = cleanName(body.name || "");
	const password = String(body.password || "");
	if (!name || !password) return json({ error: "账号和密码都要填" }, 400);

	const row = await env.DB.prepare("SELECT id, name, pass_hash, role, status FROM users WHERE name = ?")
		.bind(name)
		.first<{ id: number; name: string; pass_hash: string; role: string; status: string }>();

	if (!row) return json({ error: "账号或密码不对" }, 401);
	if (row.status !== "active") return json({ error: "这个账号已被停用" }, 403);

	const ok = await verifyPassword(password, row.pass_hash);
	if (!ok) return json({ error: "账号或密码不对" }, 401);

	const { ip, ua } = clientInfo(request);
	const now = Date.now();
	const { token, expires } = await makeSessionToken(env, row.id);

	await env.DB.prepare(
		"UPDATE users SET last_login = ?, last_ip = ?, last_ua = ?, login_count = login_count + 1 WHERE id = ?",
	)
		.bind(now, ip, ua, row.id)
		.run();

	await env.DB.prepare(
		"INSERT INTO sessions(token, user_id, created_at, expires_at, ip, ua) VALUES (?, ?, ?, ?, ?, ?)",
	)
		.bind(token, row.id, now, expires, ip, ua)
		.run();

	return json(
		{ ok: true, name: row.name, role: row.role },
		200,
		{ "Set-Cookie": sessionCookie(token, 7 * 86400) },
	);
};
