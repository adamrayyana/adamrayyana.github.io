export function GET({ site }: { site?: URL }) {
  const sitemap = new URL(`${import.meta.env.BASE_URL}sitemap-index.xml`, site ?? 'https://kannrisha.github.io');
  return new Response(`User-agent: *\nAllow: /\nSitemap: ${sitemap}\n`, {
    headers: { 'Content-Type': 'text/plain; charset=utf-8' }
  });
}
