import type { GalleryConfig } from "@/types/galleryConfig";

// 相册配置
export const galleryConfig: GalleryConfig = {
	// 相册列表
	albums: [
		// 支持jpg/png/webp/avif/gif格式
		// id: 相册唯一标识符（用于目录命名和URL路径），比如设置：id: "sparkle-2026", 对应 public/gallery/sparkle-2026/目录
		// cover: 手动指定封面图（可选，不填会把cover.*文件作为封面图，如果没有cover.*文件，则使用第一张图片作为封面图）
		// name: 相册名称
		// description: 相册描述
		// location: 相册拍摄地点
		// date: 相册日期，格式为 YYYY-MM-DD，用于排序和显示
		// tags: 相册标签，用于分类和过滤
		// password: 访问密码，设置后需要输入密码才能查看相册内容（可选）
		// passwordHint: 密码提示，设置后在输入密码错误时显示（可选，需配合password使用）
		{
			id: "sparkle",
			name: "花火 · 假面愚者",
			description:
				"「人生如戏，全靠演技。」假面愚者的头牌，最疯狂的欢愉信徒。她笑着看世界崩塌，也笑着看世界重来。",
			location: "崩坏：星穹铁道",
			date: "2026-11-09",
			tags: ["欢愉", "花火", "崩坏星穹铁道"],
		},
		{
			id: "xuzhao",
			name: "虚照 · 落笔成剧",
			description:
				"阿哈在人间的笔，也是星神最严厉的母亲。她落笔那一刻，剧本就已写好——只是没人知道下一页写的是什么。",
			location: "崩坏：星穹铁道",
			date: "2026-11-09",
			tags: ["欢愉", "虚照", "阿哈", "崩坏星穹铁道"],
		},
		{
			id: "huohua",
			name: "火花 · 燃尽欢愉",
			description:
				"欢愉队里最亮的那簇火。点燃的从来不是灯，是命——烧完了才叫痛快。",
			location: "崩坏：星穹铁道",
			date: "2026-11-09",
			tags: ["欢愉", "火花", "崩坏星穹铁道"],
		},
		{
			id: "theater",
			name: "剧场壁纸 · 欢愉之外",
			description:
				"没有角色，只有舞台：紫雾、霓虹、钟盘和永远不会散场的夜。适合当桌面壁纸的欢愉系场景。",
			location: "崩坏：星穹铁道",
			date: "2026-11-09",
			tags: ["欢愉", "壁纸", "场景"],
		},
	],

	// 瀑布流最小列宽(px)，浏览器根据容器宽度自动计算列数，默认 240
	// 值越小列数越多，值越大列数越少
	columnWidth: 260,
};
