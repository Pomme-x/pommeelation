import {
	cleanName,
	clientInfo,
	getSetting,
	hashPassword,
	json,
	logLogin,
	makeSessionToken,
	passwordStrength,
	sessionCookie,
	STRONG_PASSWORD_HINT,
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
	const code = String(body.code || "");

	if (name.length < 1 || name.length > 20) return json({ error: "账号需为 1-20 位中英文/数字/_-" }, 400);

	const strength = passwordStrength(password);
	const maxUsers = parseInt((await getSetting(env, "max_users")) || "15", 10);
	const countRow = await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first<{ n: number }>();
	const existingCount = countRow?.n || 0;
	if (existingCount >= maxUsers) return json({ error: "注册名额已满" }, 403);

	// 第一个注册的人是管理员，必须用强密码；其他人 6 位即可
	const isFirst = existingCount === 0;
	if (isFirst) {
		if (!strength.strongOk) return json({ error: STRONG_PASSWORD_HINT }, 400);
	} else if (!strength.weakOk) {
		return json({ error: "密码至少 6 位" }, 400);
	}

	const needCode = (await getSetting(env, "register_code")) || "";
	if (needCode && code !== needCode) return json({ error: "注册码不正确" }, 403);

	const exists = await env.DB.prepare("SELECT id FROM users WHERE name = ?").bind(name).first();
	if (exists) return json({ error: "这个昵称已经被用了" }, 409);

	const passHash = await hashPassword(password);
	const now = Date.now();
	const { ip, ua } = clientInfo(request);

	const res = await env.DB.prepare(
		"INSERT INTO users(name, pass_hash, role, status, created_at, last_login, last_ip, last_ua, login_count) VALUES (?, ?, ?, 'active', ?, ?, ?, ?, 1)",
	)
		.bind(name, passHash, isFirst ? "admin" : "user", now, now, ip, ua)
		.run();

	const userId = Number(res.meta?.last_row_id || 0);
	const { token, expires } = await makeSessionToken(env, userId);
	await env.DB.prepare(
		"INSERT INTO sessions(token, user_id, created_at, expires_at, ip, ua) VALUES (?, ?, ?, ?, ?, ?)",
	)
		.bind(token, userId, now, expires, ip, ua)
		.run();

	await logLogin(env, userId, name, ip, ua, true);

	return json({ ok: true, role: isFirst ? "admin" : "user" }, 200, {
		"Set-Cookie": sessionCookie(token, 7 * 86400),
	});
};
