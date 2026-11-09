import { getSetting, json, type Env } from "../../_lib/auth";

export const onRequestGet: PagesFunction<Env> = async (context) => {
	const max = parseInt((await getSetting(context.env, "max_users")) || "15", 10);
	const row = await context.env.DB.prepare("SELECT COUNT(*) AS n FROM users").first<{ n: number }>();
	return json({ used: row?.n || 0, max });
};
