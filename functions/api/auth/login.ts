import {
	cleanName,
	clientInfo,
	json,
	logLogin,
	makeSessionToken,
	sessionCookie,
	verifyPassword,
	type Env,
} from "../../_lib/auth";

const MAX_FAILS = 5;
const LOCK_MINUTES = 15;

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

	const row = await env.DB.prepare(
		"SELECT id, name, pass_hash, role, status, failed_count, locked_until FROM users WHERE name = ?",
	)
		.bind(name)
		.first<{
			id: number;
			name: string;
			pass_hash: string;
			role: string;
			status: string;
			failed_count: number;
			locked_until: number | null;
		}>();

	const { ip, ua } = clientInfo(request);
	const now = Date.now();

	if (!row) {
		// 账号不存在也写一条失败日志（用于观察撞库）
		await logLogin(env, 0, name, ip, ua, false);
		return json({ error: "账号或密码不对" }, 401);
	}

	if (row.status !== "active") {
		await logLogin(env, row.id, row.name, ip, ua, false);
		return json({ error: "这个账号已被停用" }, 403);
	}

	if (row.locked_until && row.locked_until > now) {
		const mins = Math.ceil((row.locked_until - now) / 60000);
		return json({ error: `密码错误次数太多，请 ${mins} 分钟后再试` }, 429);
	}

	const ok = await verifyPassword(password, row.pass_hash);
	if (!ok) {
		const fails = (row.failed_count || 0) + 1;
		if (fails >= MAX_FAILS) {
			await env.DB.prepare("UPDATE users SET failed_count = 0, locked_until = ? WHERE id = ?")
				.bind(now + LOCK_MINUTES * 60000, row.id)
				.run();
			await logLogin(env, row.id, row.name, ip, ua, false);
			return json({ error: `连错 ${MAX_FAILS} 次，账号锁定 ${LOCK_MINUTES} 分钟` }, 429);
		}
		await env.DB.prepare("UPDATE users SET failed_count = ? WHERE id = ?").bind(fails, row.id).run();
		await logLogin(env, row.id, row.name, ip, ua, false);
		return json({ error: `账号或密码不对（还剩 ${MAX_FAILS - fails} 次机会）` }, 401);
	}

	const { token, expires } = await makeSessionToken(env, row.id);

	await env.DB.prepare(
		"UPDATE users SET last_login = ?, last_ip = ?, last_ua = ?, login_count = login_count + 1, failed_count = 0, locked_until = NULL WHERE id = ?",
	)
		.bind(now, ip, ua, row.id)
		.run();

	await env.DB.prepare(
		"INSERT INTO sessions(token, user_id, created_at, expires_at, ip, ua) VALUES (?, ?, ?, ?, ?, ?)",
	)
		.bind(token, row.id, now, expires, ip, ua)
		.run();

	// 每个账号最多保留最近 5 个会话，旧的自动失效
	try {
		const olds = await env.DB.prepare(
			"SELECT token FROM sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT -1 OFFSET 5",
		)
			.bind(row.id)
			.all<{ token: string }>();
		for (const o of olds.results || []) {
			await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(o.token).run();
		}
	} catch {
		/* ignore */
	}

	await logLogin(env, row.id, row.name, ip, ua, true);

	return json({ ok: true, name: row.name, role: row.role }, 200, {
		"Set-Cookie": sessionCookie(token, 7 * 86400),
	});
};
