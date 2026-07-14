import { visit } from 'unist-util-visit';

const languageAliases = new Map([
  ['py', 'python'],
  ['python', 'python'],
  ['cpp', 'cpp'],
  ['c', 'c'],
  ['sh', 'shellscript'],
  ['bash', 'shellscript'],
  ['asm', 'nasm']
]);

export function remarkHackmdCompat() {
  return (tree) => {
    visit(tree, 'code', (node) => {
      const raw = (node.lang ?? '').trim().replace(/=$/, '').toLowerCase();
      if (!raw || raw === '!') {
        node.lang = 'text';
        return;
      }
      node.lang = languageAliases.get(raw) ?? raw;
    });

    visit(tree, (node) => node.type === 'containerDirective', (node) => {
      const name = String(node.name ?? '').toLowerCase();
      node.data ??= {};

      if (name === 'info') {
        node.data.hName = 'aside';
        node.data.hProperties = { className: ['callout', 'callout-info'], role: 'note' };
        node.children.unshift({
          type: 'paragraph',
          data: { hName: 'p', hProperties: { className: ['callout-label'] } },
          children: [{ type: 'text', value: 'note' }]
        });
      }

      if (name === 'attachments') {
        node.data.hName = 'aside';
        node.data.hProperties = { className: ['callout', 'attachment-panel'], 'aria-label': 'Post attachments' };
        node.children.unshift({
          type: 'paragraph',
          data: { hName: 'p', hProperties: { className: ['callout-label'] } },
          children: [{ type: 'text', value: 'downloads' }]
        });
      }

      if (name === 'spoiler') {
        const label = node.label || node.attributes?.title || 'Show details';
        node.data.hName = 'details';
        node.data.hProperties = { className: ['spoiler'] };
        node.children.unshift({
          type: 'paragraph',
          data: { hName: 'summary' },
          children: [{ type: 'text', value: label }]
        });
      }
    });
  };
}
