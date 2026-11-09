---
title: "欢愉剧场"
slug: elation-theater
published: 2026-11-09
draft: false
order: 1
description: "本站。基于 Astro + Firefly 的欢愉主题个人博客：全屏 hero 壁纸、网易云音乐直连、高清角色相册、暗紫配色。"
image: ""
status: "active"
tags:
  - Astro
  - Firefly
  - 博客
---

## 这是什么

就是我正在逛的这个站。

用 [Astro](https://astro.build/) 写的静态博客，套了 [Firefly](https://github.com/CuteLeaf/Firefly) 主题，然后按自己喜欢的「欢愉」风格改造了一遍。

## 做了什么

- **全屏 hero 壁纸**：4 张欢愉系高分辨率壁纸随机轮换，下滑时模糊渐显内容区
- **主题色**：把默认薄荷绿换成了欢愉的紫（色相 300），默认暗色模式
- **音乐播放器**：直连网易云歌单，不用自建后端
- **相册**：花火 / 虚照 / 火花 / 剧场壁纸四个分册，原图都是 2K-5K
- **评论**：准备了接入方案（Giscus / Waline），按需开启
- **搜索**：Pagefind 静态全文搜索

## 技术栈

| 层 | 技术 |
| --- | --- |
| 框架 | Astro 7 |
| 交互 | Svelte 5 |
| 样式 | Tailwind CSS |
| 搜索 | Pagefind |
| 部署 | GitHub Pages |
| 主题 | Firefly 6.16 |

## 以后想加的

- 周报自动归档
- PDF 一键转文章的小工具（正在做）
