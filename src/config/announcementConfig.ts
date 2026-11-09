import type { AnnouncementConfig } from "../types/announcementConfig";

export const announcementConfig: AnnouncementConfig = {
	// 公告标题，留空则走i18n默认标题
	title: "开演通知",

	// 公告内容
	content:
		"欢愉剧场今日开演。阿哈说：不必鼓掌，只要笑出来就好。这里的每篇文章都是一场即兴演出，欢迎随时入座。",

	// 是否允许用户关闭公告
	closable: true,

	link: {
		// 启用链接
		enable: true,
		// 链接文本
		text: "认识一下剧场老板",
		// 链接 URL
		url: "/about/",
		// 内部链接
		external: false,
	},
};
