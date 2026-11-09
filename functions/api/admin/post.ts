import { json, requireAdmin, type Env } from "../../_lib/auth";
import { ghDeleteFile, ghGetFile, ghPutFile } from "../../_lib/github";

export interface EnvWithGithub extends Env {
	GITHUB_TOKEN?: string;
	GITHUB_REPO?: string;
	GITHUB_BRANCH?: string;
}

const POST_DIR = "src/content/posts";

function yamlStr(s: string): string {
	return '"' + String(s || "").replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
}

function buildFront(data: any): string {
	const lines = ["---"];
	lines.push("title: " + yamlStr(data.title || "未命名"));
	lines.push("published: " + (data.published || new Date().toISOString().slice(0, 10)));
	if (data.description) lines.push("description: " + yamlStr(data.description));
	const tags = Array.isArray(data.tags) ? data.tags.filter(Boolean) : [];
	if (tags.length) lines.push("tags: [" + tags.map((t: string) => yamlStr(t)).join(", ") + "]");
	if (data.category) lines.push("category: " + yamlStr(data.category));
	if (data.slug) lines.push("slug: " + yamlStr(data.slug));
	if (data.pinned) lines.push("pinned: true");
	if (data.draft) lines.push("draft: true");
	lines.push("---", "");
	return lines.join("\n");
}

function parseFront(text: string) {
	const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/.exec(text || "");
	const fm: Record<string, any> = {};
	let body = text || "";
	if (!m) return { fm, body };
	body = text.slice(m[0].length);
	for (const line of m[1].split(/\r?\n/)) {
		const t = line.trim();
		if (!t || t.startsWith("#")) continue;
		const i = t.indexOf(":");
		if (i < 0) continue;
		const key = t.slice(0, i).trim();
		let val = t.slice(i + 1).trim();
		if (val.startsWith("[") && val.endsWith("]")) {
			val = val
				.slice(1, -1)
				.split(",")
				.map((s: string) => s.trim().replace(/^["']|["']$/g, ""))
				.filter(Boolean);
		} else if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
			val = val.slice(1, -1);
		}
		fm[key] = val;
	}
	return { fm, body };
}

export const onRequestGet: PagesFunction<EnvWithGithub> = async (context) => {
	const admin = await requireAdmin(context.env, context.request);
	if (!admin) return json({ error: "没有权限" }, 403);

	const path = new URL(context.request.url).searchParams.get("path") || "";
	if (!path.startsWith(POST_DIR + "/")) return json({ error: "路径不合法" }, 400);
	const file = await ghGetFile(context.env, path);
	if (!file) return json({ error: "文章不存在" }, 404);
	const { fm, body } = parseFront(file.content);
	return json({
		path,
		title: fm.title || "",
		published: fm.published || "",
		description: fm.description || "",
		category: fm.category || "",
		tags: Array.isArray(fm.tags) ? fm.tags : fm.tags ? [fm.tags] : [],
		slug: fm.slug || "",
		pinned: String(fm.pinned).toLowerCase() === "true",
		draft: String(fm.draft).toLowerCase() === "true",
		body,
	});
};

export const onRequestPost: PagesFunction<EnvWithGithub> = async (context) => {
	const admin = await requireAdmin(context.env, context.request);
	if (!admin) return json({ error: "没有权限" }, 403);

	let data: any;
	try {
		data = await context.request.json();
	} catch {
		return json({ error: "请求格式错误" }, 400);
	}

	const slug =
		String(data.slug || "")
			.trim()
			.toLowerCase()
			.replace(/[^a-z0-9-]+/g, "-")
			.replace(/^-+|-+$/g, "") ||
		"post-" + Date.now().toString(36);

	const path = POST_DIR + "/" + slug + ".md";
	const content = buildFront({ ...data, slug }) + String(data.body || "");
	const r = await ghPutFile(context.env, path, content, "feat: " + (data.title || "更新文章"));
	if (!r.ok) return json({ error: r.error || "保存失败" }, 500);
	return json({ ok: true, path, url: admin.role === "admin" ? path : path });
};

export const onRequestDelete: PagesFunction<EnvWithGithub> = async (context) => {
	const admin = await requireAdmin(context.env, context.request);
	if (!admin) return json({ error: "没有权限" }, 403);

	const path = new URL(context.request.url).searchParams.get("path") || "";
	if (!path.startsWith(POST_DIR + "/")) return json({ error: "路径不合法" }, 400);
	const r = await ghDeleteFile(context.env, path, "chore: 删除文章 " + path);
	if (!r.ok) return json({ error: r.error || "删除失败" }, 500);
	return json({ ok: true });
};
