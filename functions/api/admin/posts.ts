import { json, requireAdmin, type Env } from "../../_lib/auth";
import { ghGetFile, ghListDir } from "../../_lib/github";

export interface EnvWithGithub extends Env {
	GITHUB_TOKEN?: string;
	GITHUB_REPO?: string;
	GITHUB_BRANCH?: string;
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

	const files = await ghListDir(context.env, "src/content/posts");
	const posts = [];
	for (const f of files) {
		if (!/\.(md|mdx)$/i.test(f.name)) continue;
		const file = await ghGetFile(context.env, f.path);
		if (!file) continue;
		const { fm, body } = parseFront(file.content);
		posts.push({
			path: f.path,
			name: f.name,
			title: fm.title || f.name.replace(/\.(md|mdx)$/i, ""),
			published: fm.published || "",
			category: fm.category || "",
			tags: Array.isArray(fm.tags) ? fm.tags : fm.tags ? [fm.tags] : [],
			description: fm.description || "",
			draft: String(fm.draft).toLowerCase() === "true",
			pinned: String(fm.pinned).toLowerCase() === "true",
			size: body.length,
		});
	}
	posts.sort((a, b) => String(b.published).localeCompare(String(a.published)));
	return json({ posts });
};
