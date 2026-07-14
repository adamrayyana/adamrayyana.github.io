import rss from '@astrojs/rss';
import { siteConfig } from '../config/site';
import { getPosts, postSlug } from '../lib/posts';

export async function GET(context: { site?: URL }) {
  const posts = await getPosts();
  const base = import.meta.env.BASE_URL.replace(/\/$/, '');
  return rss({
    title: siteConfig.title,
    description: siteConfig.description,
    site: context.site ?? 'https://adamrayyana.github.io',
    items: posts.map((post) => ({
      title: post.data.title,
      description: post.data.description,
      ...(post.data.publishedAt ? { pubDate: post.data.publishedAt } : {}),
      link: `${base}/posts/${postSlug(post)}/`,
      categories: post.data.tags
    })),
    customData: '<language>en-us</language>'
  });
}
