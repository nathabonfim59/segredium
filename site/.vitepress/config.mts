import { copyFileSync, existsSync, mkdirSync, readdirSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineConfig, type DefaultTheme } from 'vitepress'

const docsDir = fileURLToPath(new URL('../../docs', import.meta.url))

// One sidebar entry per generated Go package page (see scripts/docs-api.mjs).
function goPackageItems(): DefaultTheme.SidebarItem[] {
  const goDir = join(docsDir, 'api-reference', 'go')
  const items: DefaultTheme.SidebarItem[] = []
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name)
      if (entry.isDirectory()) walk(path)
      else if (entry.name === 'index.md' && dir !== goDir) {
        const rel = relative(goDir, dir).split('\\').join('/')
        items.push({ text: rel, link: `/api-reference/go/${rel}/` })
      }
    }
  }
  if (existsSync(goDir)) walk(goDir)
  return items.sort((a, b) => a.text!.localeCompare(b.text!))
}

// Copy the hand-written pages into the output as .md files, so llms.txt can link to markdown.
// The generated API reference is left out: it is large and has its own HTML pages.
function copyMarkdown(outDir: string) {
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name)
      const rel = relative(docsDir, path).split('\\').join('/')
      if (entry.isDirectory()) {
        if (entry.name !== 'api-reference' && entry.name !== 'public') walk(path)
      } else if (entry.name.endsWith('.md') && rel !== 'index.md' && rel !== 'development.md') {
        mkdirSync(dirname(join(outDir, rel)), { recursive: true })
        copyFileSync(path, join(outDir, rel))
      }
    }
  }
  walk(docsDir)
}

// The pages live in ../docs so the same Markdown ships in the packages.
export default defineConfig({
  title: 'segredium',
  description: 'A self-hostable, fully local AWS Secrets Manager for dev and tests.',
  srcDir: '../docs',
  base: '/segredium/',
  cleanUrls: true,
  lastUpdated: true,
  srcExclude: ['development.md'],
  buildEnd: ({ outDir }) => copyMarkdown(outDir),
  themeConfig: {
    nav: [
      { text: 'Docs', link: '/install/', activeMatch: '^/(install|setup|configuration|security|compatibility|api-reference)' },
      { text: 'Releases', link: 'https://github.com/nathabonfim59/segredium/releases' },
    ],
    sidebar: [
      {
        text: 'Install',
        items: [
          { text: 'Overview', link: '/install/' },
          { text: 'Debian and Ubuntu', link: '/install/debian' },
          { text: 'Fedora, RHEL and derivatives', link: '/install/rpm' },
          { text: 'Alpine', link: '/install/alpine' },
          { text: 'Static binary', link: '/install/binary' },
          { text: 'Build from source', link: '/install/source' },
        ],
      },
      {
        text: 'Set up clients',
        items: [
          { text: 'Route and trust', link: '/setup' },
          { text: 'First run and checks', link: '/install/verify' },
          { text: 'Upgrade and remove', link: '/install/upgrade' },
          { text: 'Troubleshooting', link: '/install/troubleshooting' },
        ],
      },
      {
        text: 'Reference',
        items: [
          { text: 'Configuration', link: '/configuration' },
          { text: 'Security model', link: '/security' },
          { text: 'API compatibility', link: '/compatibility' },
        ],
      },
      {
        text: 'Go API reference',
        collapsed: true,
        items: [{ text: 'Overview', link: '/api-reference/go/' }, ...goPackageItems()],
      },
    ],
    socialLinks: [{ icon: 'github', link: 'https://github.com/nathabonfim59/segredium' }],
    editLink: {
      pattern: 'https://github.com/nathabonfim59/segredium/edit/main/docs/:path',
    },
    search: { provider: 'local' },
    outline: { label: 'Contents', level: [2, 3] },
    footer: { message: 'Released under the MIT License.' },
  },
})
