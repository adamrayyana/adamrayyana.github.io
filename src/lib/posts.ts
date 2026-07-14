import { getCollection, type CollectionEntry } from 'astro:content';
import readingTime from 'reading-time';

export type Post = CollectionEntry<'posts'>;

export function postSlug(post: Post) {
  return post.id.replace(/\\/g, '/').replace(/\/index(?:\.(md|mdx))?$/i, '').replace(/\.(md|mdx)$/i, '');
}

export function tagSlug(tag: string) {
  return tag.toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

export function postStats(post: Post) {
  const stats = readingTime(post.body ?? '');
  return { minutes: Math.max(1, Math.ceil(stats.minutes)), words: stats.words };
}

export function isPostVisible(post: Post) {
  if (import.meta.env.DEV) return true;
  if (post.data.draft) return false;
  return !post.data.publishedAt || post.data.publishedAt <= new Date();
}

export async function getPosts() {
  const posts = (await getCollection('posts')).filter(isPostVisible);
  return posts.sort((a, b) => {
    const aDate = a.data.publishedAt?.getTime() ?? 0;
    const bDate = b.data.publishedAt?.getTime() ?? 0;
    return bDate - aDate || a.data.title.localeCompare(b.data.title);
  });
}

export function allTags(posts: Post[]) {
  const counts = new Map<string, number>();
  posts.forEach((post) => post.data.tags.forEach((tag) => counts.set(tag, (counts.get(tag) ?? 0) + 1)));
  return [...counts.entries()].sort(([a], [b]) => a.localeCompare(b));
}
