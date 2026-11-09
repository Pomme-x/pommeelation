import { clearCookie, getCookie, json, type Env } from "../../_lib/auth";

export const onRequestPost: PagesFunction<Env> = async (context) => {
	const { request, env } = context;
	const token = getCookie(request);
	if (token) {
		try {
			await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
		} catch {
			/* ignore */
		}
	}
	return json({ ok: true }, 200, { "Set-Cookie": clearCookie() });
};
