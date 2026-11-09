/**
 * 用 GitHub Contents API 读写仓库文件（管理后台用）
 * token 存在 Cloudflare Secret 里，绝不下发到前端
 */

export interface GithubEnv {
	DB: D1Database;
	AUTH_SECRET: string;
	GITHUB_TOKEN?: string;
	GITHUB_REPO?: string;
	GITHUB_BRANCH?: string;
}

export interface GHFile {
	path: string;
	sha: string;
	content: string;
}

function repo(env: GithubEnv): string {
	return env.GITHUB_REPO || "Pomme-x/pommeelation";
}

function branch(env: GithubEnv): string {
	return env.GITHUB_BRANCH || "master";
}

function headers(env: GithubEnv): Record<string, string> {
	return {
		Authorization: "Bearer " + (env.GITHUB_TOKEN || ""),
		Accept: "application/vnd.github+json",
		"User-Agent": "elation-admin",
		"X-GitHub-Api-Version": "2022-11-28",
	};
}

export async function ghGetFile(env: GithubEnv, path: string): Promise<GHFile | null> {
	const url = `https://api.github.com/repos/${repo(env)}/contents/${encodeURIComponent(path).replace(/%2F/g, "/")}?ref=${branch(env)}`;
	const res = await fetch(url, { headers: headers(env) });
	if (res.status === 404) return null;
	if (!res.ok) throw new Error("GitHub 读取失败：" + res.status);
	const data: any = await res.json();
	if (Array.isArray(data)) return null;
	let content = "";
	if (data.content) {
		const bin = atob(String(data.content).replace(/\n/g, ""));
		const bytes = new Uint8Array(bin.length);
		for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
		content = new TextDecoder().decode(bytes);
	}
	return { path, sha: data.sha, content };
}

export async function ghPutFile(
	env: GithubEnv,
	path: string,
	content: string,
	message: string,
): Promise<{ ok: boolean; sha?: string; error?: string }> {
	const existing = await ghGetFile(env, path);
	const body: any = {
		message,
		content: btoa(unescape(encodeURIComponent(content))),
		branch: branch(env),
	};
	if (existing) body.sha = existing.sha;
	const url = `https://api.github.com/repos/${repo(env)}/contents/${encodeURIComponent(path).replace(/%2F/g, "/")}`;
	const res = await fetch(url, { method: "PUT", headers: headers(env), body: JSON.stringify(body) });
	if (!res.ok) {
		const t = await res.text();
		return { ok: false, error: `${res.status} ${t.slice(0, 160)}` };
	}
	const data: any = await res.json();
	return { ok: true, sha: data.content?.sha };
}

export async function ghDeleteFile(
	env: GithubEnv,
	path: string,
	message: string,
): Promise<{ ok: boolean; error?: string }> {
	const existing = await ghGetFile(env, path);
	if (!existing) return { ok: false, error: "文件不存在" };
	const url = `https://api.github.com/repos/${repo(env)}/contents/${encodeURIComponent(path).replace(/%2F/g, "/")}`;
	const res = await fetch(url, {
		method: "DELETE",
		headers: headers(env),
		body: JSON.stringify({ message, sha: existing.sha, branch: branch(env) }),
	});
	if (!res.ok) return { ok: false, error: `${res.status}` };
	return { ok: true };
}

/** 列出目录下的文件（只返回文件名和路径） */
export async function ghListDir(
	env: GithubEnv,
	dir: string,
): Promise<{ name: string; path: string; sha: string }[]> {
	const url = `https://api.github.com/repos/${repo(env)}/contents/${encodeURIComponent(dir).replace(/%2F/g, "/")}?ref=${branch(env)}`;
	const res = await fetch(url, { headers: headers(env) });
	if (!res.ok) return [];
	const data: any = await res.json();
	if (!Array.isArray(data)) return [];
	return data.map((e: any) => ({ name: e.name, path: e.path, sha: e.sha }));
}

/** 触发一次重新部署（可选：workflow_dispatch） */
export async function ghDispatchDeploy(env: GithubEnv): Promise<boolean> {
	const url = `https://api.github.com/repos/${repo(env)}/actions/workflows/deploy.yml/dispatches`;
	const res = await fetch(url, {
		method: "POST",
		headers: headers(env),
		body: JSON.stringify({ ref: branch(env) }),
	});
	return res.ok || res.status === 204;
}
