import {
	currentUser,
	hashPassword,
	json,
	passwordStrength,
	STRONG_PASSWORD_HINT,
	verifyPassword,
	type Env,
} from "../../_lib/auth";

/** 修改自己的密码：必须验证旧密码；管理员账号强制强密码 */
export const onRequestPost: PagesFunction<Env> = async (context) => {
	const user = await currentUser(context.env, context.request);
	if (!user) return json({ error: "未登录" }, 401);

	let body: any;
	try {
		body = await context.request.json();
	} catch {
		return json({ error: "请求格式错误" }, 400);
	}

	const oldPwd = String(body.old || "");
	const newPwd = String(body.next || "");
	if (!oldPwd || !newPwd) return json({ error: "旧密码和新密码都要填" }, 400);

	const row = await context.env.DB.prepare("SELECT id, pass_hash, role FROM users WHERE id = ?")
		.bind(user.id)
		.first<{ id: number; pass_hash: string; role: string }>();
	if (!row) return json({ error: "用户不存在" }, 404);

	const ok = await verifyPassword(oldPwd, row.pass_hash);
	if (!ok) return json({ error: "旧密码不对" }, 401);

	const strength = passwordStrength(newPwd);
	if (row.role === "admin") {
		if (!strength.strongOk) return json({ error: STRONG_PASSWORD_HINT }, 400);
	} else if (!strength.weakOk) {
		return json({ error: "密码至少 6 位" }, 400);
	}

	const hash = await hashPassword(newPwd);
	const now = Date.now();

	await context.env.DB.prepare(
		"UPDATE users SET pass_hash = ?, failed_count = 0, locked_until = NULL WHERE id = ?",
	)
		.bind(hash, row.id)
		.run();

	// 踢掉除当前会话外的其他会话
	const cookie = (context.request.headers.get("Cookie") || "")
		.split(";")
		.map((s) => s.trim())
		.find((s) => s.startsWith("ff_auth="));
	const token = cookie ? cookie.slice("ff_auth=".length) : "";
	await context.env.DB.prepare("DELETE FROM sessions WHERE user_id = ? AND token != ?")
		.bind(row.id, token)
		.run();

	// 记录一次安全日志
	try {
		await context.env.DB.prepare(
			"INSERT INTO login_logs(user_id, name, ip, ua, at, ok) VALUES (?, ?, ?, ?, ?, 1)",
		)
			.bind(
				row.id,
				user.name,
				context.request.headers.get("CF-Connecting-IP") || "unknown",
				"修改密码",
				now,
			)
			.run();
	} catch {
		/* ignore */
	}

	return json({ ok: true });
};
