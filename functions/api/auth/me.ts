import { currentUser, json, type Env } from "../../_lib/auth";

export const onRequestGet: PagesFunction<Env> = async (context) => {
	const user = await currentUser(context.env, context.request);
	if (!user) return json({ user: null }, 200);
	return json({
		user: {
			id: user.id,
			name: user.name,
			role: user.role,
			created_at: user.created_at,
			last_login: user.last_login,
			last_ip: user.last_ip,
			login_count: user.login_count,
		},
	});
};
