import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';
import remarkDirective from 'remark-directive';
import remarkGfm from 'remark-gfm';
import { remarkHackmdCompat } from './src/lib/remark-hackmd-compat.mjs';

const site = process.env.SITE_URL ?? 'https://adamrayyana.github.io';
const base = process.env.BASE_PATH ?? '/';

export default defineConfig({
  site,
  base,
  output: 'static',
  integrations: [sitemap()],
  markdown: {
    remarkPlugins: [remarkGfm, remarkDirective, remarkHackmdCompat],
    shikiConfig: {
      themes: {
        light: 'github-light',
        dark: 'github-dark'
      },
      defaultColor: false,
      langAlias: {
        py: 'python',
        sh: 'shellscript',
        asm: 'nasm'
      }
    }
  }
});
