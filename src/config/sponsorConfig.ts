import type { SponsorConfig } from "../types/sponsorConfig";

export const sponsorConfig: SponsorConfig = {
	// 页面标题，如果留空则使用 i18n 中的翻译
	title: "请 Pomme 喝杯奶茶",

	// 页面描述文本，如果留空则使用 i18n 中的翻译
	description: "如果这里的东西让你笑了或者帮到你，可以随缘支持一下。",

	// 打赏用途说明
	usage:
		"打赏会用来补贴域名和服务器开销，以及偶尔给自己买点好吃的。不赏也没关系，来玩就已经很开心了。",

	// 是否显示打赏者列表
	showSponsorsList: false,

	// 是否显示评论区，需要先在commentConfig.ts启用评论系统
	showComment: true,

	// 是否在文章详情页底部显示打赏按钮
	showButtonInPost: true,

	// 打赏方式列表（只保留微信赞赏码）
	methods: [
		{
			name: "微信赞赏码",
			icon: "fa7-brands:weixin",
			// 收款码图片路径（需要放在 public 目录下）
			qrCode: "/assets/images/sponsor/wechat-pay.jpg",
			link: "",
			description: "打开微信扫一扫，随缘投喂",
			enabled: true,
		},
	],

	// 打赏者列表（可选）
	sponsors: [],
};
