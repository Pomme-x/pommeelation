import type { BackgroundWallpaperConfig } from "@/types/backgroundWallpaper";

export const backgroundWallpaper: BackgroundWallpaperConfig = {
	// 壁纸模式："banner" 横幅壁纸，"fullscreen" 全屏壁纸，"overlay" 覆盖透明，"none" 纯色背景无壁纸
	mode: "fullscreen",
	// 是否启用背景视频播放，配置后将在导航栏显示视频播放按钮
	playerEnable: false,
	/**
	 * 背景图片配置
	 * 图片路径支持三种格式：
	 * 1. public 目录（以 "/" 开头，不优化）："/assets/images/banner.avif"
	 * 2. src 目录（不以 "/" 开头，自动优化但会增加构建时间，推荐）："assets/images/banner.avif"
	 * 3. 远程 URL："https://example.com/banner.jpg"
	 */
	src: {
		// 桌面背景图片（多张随机，每次刷新换一张）
		desktop: [
			"assets/images/DesktopWallpaper/h1.webp",
			"assets/images/DesktopWallpaper/h2.webp",
			"assets/images/DesktopWallpaper/h3.webp",
			"assets/images/DesktopWallpaper/h4.webp",
		],
		// 移动背景图片
		mobile: [
			"assets/images/MobileWallpaper/m1.webp",
			"assets/images/MobileWallpaper/m2.webp",
			"assets/images/MobileWallpaper/m3.webp",
		],
		// 背景视频播放地址
		playerUrl: "",
	},
	// 横幅壁纸和全屏壁纸共享配置
	common: {
		// 壁纸遮罩暗度，让横幅文字显示更清晰，0-1之间，值越大越暗
		dimOpacity: 0.25,
		// 多视频播放模式："order" 顺序循环，"random" 随机切换（仅当 playerUrl 为数组时生效）
		playerMode: "random",
		// 主页横幅文字
		homeText: {
			// 是否启用主页横幅文字
			enable: true,
			// 主页横幅主标题
			title: "欢愉剧场",
			// 主页横幅主标题字体大小
			titleSize: "4.5rem",
			// 主页横幅副标题
			subtitle: [
				"阿哈在观众席上，笑得直不起腰",
				"花火说：人生如戏，全靠演技",
				"虚照落笔那一刻，世界便成了剧本",
				"火花点燃的，从来不是灯，是命",
				"欢迎来到欢愉剧场，请对号入座",
				"这里没有散场，只有下一幕",
			],
			// 主页横幅副标题字体大小
			subtitleSize: "1.5rem",
			typewriter: {
				// 是否启用打字机效果
				// 打字机开启 → 循环显示所有副标题
				// 打字机关闭 → 每次刷新随机显示一条副标题
				enable: true,
				// 打字速度（毫秒）
				speed: 110,
				// 删除速度（毫秒）
				deleteSpeed: 55,
				// 完全显示后的暂停时间（毫秒）
				pauseTime: 2200,
			},
			// 是否显示标题下方的链接图标
			linksEnable: true,
			// 首页横幅标题下方的链接图标
			links: [
				{
					name: "归档",
					icon: "material-symbols:archive",
					url: "/archive/",
					showName: true,
				},
				{
					name: "归档",
					icon: "material-symbols:music-note",
					url: "/archive/",
					showName: false,
				},
				{
					name: "RSS",
					icon: "fa7-solid:rss",
					url: "/rss/",
					showName: false,
				},
			],
		},
		// 壁纸轮播配置，横幅壁纸和全屏壁纸共享，仅在配置多张图片时生效
		carousel: {
			// 是否启用壁纸轮播；关闭时保持每次刷新随机显示一张
			enable: false,
			// 轮播切换间隔（毫秒）
			interval: 6000,
			// 过渡效果: 'fade' 渐变 | 'zoom' 缩放 | 'slide' 滑动 | 'kenburns' 旋转木马
			transitionEffect: "kenburns",
		},
		// 水波纹动画效果配置，开启会影响页面性能，增加内存占用
		waves: {
			enable: {
				// 桌面端是否启用水波纹动画效果
				desktop: true,
				// 移动端是否启用水波纹动画效果
				mobile: false,
			},
		},
		// 渐变过渡效果配置，当水波纹关闭时自动启用
		gradient: {
			enable: {
				// 桌面端是否启用渐变过渡
				desktop: true,
				// 移动端是否启用渐变过渡
				mobile: true,
			},
			// 渐变高度
			height: "12%",
		},
	},
	// Banner模式特有配置
	banner: {
		// 图片位置
		position: "0% 20%",
		// 文章横幅信息："description" 显示描述，"meta" 显示日期、字数和阅读时长
		postInfo: {
			mode: "description",
		},
		// 导航栏配置
		navbar: {
			// 导航栏透明模式："semi" 半透明，"semifull" 动态透明，"none" 纯色不透明
			transparentMode: "semi",
			// 毛玻璃模糊度，0 即关闭导航栏的毛玻璃
			blur: 12,
		},
	},
	// 覆盖透明覆盖模式特有配置
	overlay: {
		// 层级，确保壁纸在背景层
		zIndex: -1,
		// 壁纸透明度
		opacity: 0.9,
		// 背景模糊度
		blur: 12,
		// 卡片透明度，0-1之间，值越小越透明
		cardOpacity: 0.55,
	},
	// 全屏壁纸模式特有配置
	fullscreen: {
		// 布局模式："classic" 经典文档流全屏壁纸，"hero" 固定全屏首屏壁纸
		layout: "hero",
		// 图片位置
		position: "center",
		// 全屏壁纸模式的导航栏配置
		navbar: {
			// 导航栏透明模式："semi" 半透明，"semifull" 动态透明
			transparentMode: "semifull",
			// 导航栏毛玻璃模糊度，0 即关闭（玻璃态生效）
			blur: 12,
		},
		// 首页下滑时壁纸模糊渐变开关
		blurRamp: {
			enable: {
				// 桌面端是否启用模糊渐变
				desktop: true,
				// 移动端是否启用模糊渐变
				mobile: true,
			},
		},
	},
};
