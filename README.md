# Kannrisha's field notes

A static Astro blog for CTF writeups, binary exploitation notes, and technical experiments.

## Local development

```sh
npm install
npm run dev
```

Run `npm run check` for Astro and TypeScript diagnostics. `npm run build` creates the production site and its Pagefind search index in `dist/`.

## Add a post

Create `src/content/posts/my-post/index.md`:

```md
---
title: My post
description: A short summary for cards, search, and feeds.
publishedAt: 2026-07-14
tags: [CTF, pwn]
draft: false
featured: false
---

# My post

Start writing here.
```

Images and downloadable files can live in the same folder as `index.md`. Omit `publishedAt` when the date is unknown. Set `draft: true` to keep a post out of production lists, search, feeds, and generated routes.

HackMD-style `:::info` and `:::spoiler[label]` containers are supported, along with fence labels such as `py=` and `cpp=`. Existing HackMD spoiler headings can be migrated by wrapping the label in brackets.

## Deploy

Push to `main`, enable **GitHub Actions** as the Pages source in the repository settings, and the included workflow will deploy the site at the repository subpath. For a custom domain, set `SITE_URL` to the domain, set `BASE_PATH` to `/`, and add `public/CNAME`.
