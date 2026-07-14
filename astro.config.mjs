import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';
import remarkDirective from 'remark-directive';
import remarkGfm from 'remark-gfm';
import { remarkHackmdCompat } from './src/lib/remark-hackmd-compat.mjs';

const site = process.env.SITE_URL ?? 'https://adamrayyana.github.io';
const base = process.env.BASE_PATH ?? '/';

const terminalDark = {
  name: 'kannrisha-dark',
  type: 'dark',
  colors: {
    'editor.background': '#111111',
    'editor.foreground': '#dddddd'
  },
  tokenColors: [
    { scope: ['comment', 'punctuation.definition.comment'], settings: { foreground: '#777777', fontStyle: 'italic' } },
    { scope: ['keyword', 'keyword.control', 'storage', 'storage.type'], settings: { foreground: '#ff8fbe' } },
    { scope: ['invalid', 'invalid.illegal'], settings: { foreground: '#ff8fbe' } }
  ]
};

const terminalLight = {
  name: 'kannrisha-light',
  type: 'light',
  colors: {
    'editor.background': '#eeeeee',
    'editor.foreground': '#292929'
  },
  tokenColors: [
    { scope: ['comment', 'punctuation.definition.comment'], settings: { foreground: '#888888', fontStyle: 'italic' } },
    { scope: ['keyword', 'keyword.control', 'storage', 'storage.type'], settings: { foreground: '#a31355' } },
    { scope: ['invalid', 'invalid.illegal'], settings: { foreground: '#a31355' } }
  ]
};

export default defineConfig({
  site,
  base,
  output: 'static',
  integrations: [sitemap()],
  markdown: {
    remarkPlugins: [remarkGfm, remarkDirective, remarkHackmdCompat],
    shikiConfig: {
      themes: {
        light: terminalLight,
        dark: terminalDark
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
