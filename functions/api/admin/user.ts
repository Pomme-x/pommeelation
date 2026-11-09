import { hashPassword, json, requireAdmin, type Env } from "../../_lib/auth";

export const onRequestPost: PagesFunction<Env> = async (context) => {
	const admin = await requireAdmin(context.env, context.request);
	if (!admin) return json({ error: "没有权限" }, 403);

	let body: any;
	try {
		body = await context.request.json();
	} catch {
		return json({ error: "请求格式错误" }, 400);
	}

	const id = parseInt(String(body.id || "0"), 10);
	const action = String(body.action || "");
	if (!id) return json({ error: "缺少用户 id" }, 400);

	const target = await context.env.DB.prepare("SELECT id, name, role FROM users WHERE id = ?")
		.bind(id)
		.first<{ id: number; name: string; role: string }>();
	if (!target) return json({ error: "用户不存在" }, 404);

	if (id === admin.id && action !== "password") {
		return json({ error: "不能对自己做这个操作" }, 400);
	}

	switch (action) {
		case "ban":
			await context.env.DB.prepare("UPDATE users SET status = 'banned' WHERE id = ?").bind(id).run();
			await context.env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(id).run();
			return json({ ok: true });
		case "unban":
			await context.env.DB.prepare("UPDATE users SET status = 'active' WHERE id = ?").bind(id).run();
			return json({ ok: true });
		case "role":
			await context.env.DB.prepare("UPDATE users SET role = ? WHERE id = ?")
				.bind(body.value === "admin" ? "admin" : "user", id)
				.run();
			return json({ ok: true });
		case "password": {
			const pwd = String(body.value || "");
			if (pwd.length < 6) return json({ error: "密码至少 6 位" }, 400);
			const hash = await hashPassword(pwd);
			await context.env.DB.prepare("UPDATE users SET pass_hash = ? WHERE id = ?").bind(hash, id).run();
			await context.env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(id).run();
			return json({ ok: true });
		}
		case "delete":
			await context.env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(id).run();
			await context.env.DB.prepare("DELETE FROM users WHERE id = ?").bind(id).run();
			return json({ ok: true });
		default:
			return json({ error: "未知操作" }, 400);
	}
};
