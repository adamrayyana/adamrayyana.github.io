export const siteConfig = {
  name: 'kannrisha',
  title: "kannrisha",
  description: 'A couple of notes from what I\'ve learned',
  handle: 'kannrisha',
  intro: 'I like breaking things. Here, I post stuff I learned while doing CTFs and other stuff.',
  about: {
    eyebrow: 'Profile data pending',
    lead: 'This page is ready for the story behind kannrisha.',
    paragraphs: [
      'Replace this placeholder with a short introduction: what you study or build, how you got into security, and what readers can expect from these notes.',
      'You can also add a longer timeline, current interests, CTF team details, or contact preferences whenever you are ready.'
    ]
  },
  social: [
    { label: 'GitHub', href: 'https://github.com/adamrayyana', icon: 'github' },
    { label: 'LinkedIn', href: 'https://www.linkedin.com/in/adamrayyana/', icon: 'linkedin' },
    { label: 'Discord', href: 'https://discord.com/users/247347746854404097', icon: 'discord' },
    { label: 'Email', href: 'mailto:adam.rayyan.a@gmail.com', icon: 'email' }
  ] as Array<{ label: string; href: string; icon: 'github' | 'linkedin' | 'discord' | 'email' }>
};
