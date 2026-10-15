// @ts-check
import starlight from '@astrojs/starlight'
import { defineConfig } from 'astro/config'
import starlightOpenAPI, { openAPISidebarGroups } from 'starlight-openapi'

// GitHub Pages project sites live under /<repo>/. The deploy workflow sets SITE_URL and SITE_BASE;
// locally both are unset and the site is served from the root.
const site = process.env.SITE_URL || 'https://booker-dragon.github.io'
const base = process.env.SITE_BASE || '/'

export default defineConfig({
  site,
  base,
  trailingSlash: 'always',
  integrations: [
    starlight({
      title: 'iAM Smart API',
      description: 'Interactive documentation for the iAM Smart API Specification v2.5.2: endpoints, callbacks, request signing, encryption and developer tools.',
      logo: { src: './src/assets/logo.svg', alt: 'iAM Smart API docs' },
      favicon: '/favicon.svg',
      customCss: ['./src/styles/custom.css'],
      components: {
        // Injects the interactive "Try it" console into every API reference page.
        MarkdownContent: './src/components/overrides/MarkdownContent.astro',
      },
      lastUpdated: false,
      social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/booker-dragon/iam-smart-docs' }],
      editLink: { baseUrl: 'https://github.com/booker-dragon/iam-smart-docs/edit/main/' },
      plugins: [
        starlightOpenAPI([
          {
            base: 'api',
            schema: './schemas/iam-smart-api.yaml',
            sidebar: {
              label: 'API reference',
              operations: { badges: true, labels: 'summary' },
            },
            // The API needs signed + encrypted bodies, so generic curl/fetch snippets would be wrong.
            // Every operation ships authored x-codeSamples instead (Node.js reference client + wire format).
            snippets: { operation: false },
          },
        ]),
      ],
      sidebar: [
        {
          label: 'Start here',
          items: [
            { label: 'Overview', slug: 'start/overview' },
            { label: 'Onboarding & environments', slug: 'start/onboarding' },
            { label: 'Quick start: log in a user', slug: 'start/quick-start' },
          ],
        },
        {
          label: 'Security',
          items: [
            { label: 'Request signing', slug: 'security/signing' },
            { label: 'Encryption', slug: 'security/encryption' },
            { label: 'Receiving callbacks', slug: 'security/callbacks' },
          ],
        },
        {
          label: 'Guides',
          items: [
            { label: 'Authentication', slug: 'guides/authentication' },
            { label: 'Profiles', slug: 'guides/profiles' },
            { label: 'Form Filling', slug: 'guides/form-filling' },
            { label: 'Anonymous Form Filling', slug: 'guides/anonymous-form-filling' },
            { label: 'Digital Signing', slug: 'guides/digital-signing' },
            { label: 'Anonymous Digital Signing', slug: 'guides/anonymous-digital-signing' },
            { label: 'Re-authentication', slug: 'guides/re-authentication' },
            { label: 'Bulk Digital Signing', slug: 'guides/bulk-digital-signing' },
            { label: 'Anonymous Bulk Signing', slug: 'guides/anonymous-bulk-digital-signing' },
            { label: 'Step-up Authentication', slug: 'guides/step-up-authentication' },
            { label: 'Anonymous Step-up', slug: 'guides/anonymous-step-up-authentication' },
            { label: 'CDEG Integration', slug: 'guides/cdeg' },
            { label: 'Reference client', slug: 'guides/client' },
            { label: 'Local mock server', slug: 'guides/mock-server' },
          ],
        },
        { label: 'Developer tools', slug: 'tools', badge: { text: 'Interactive', variant: 'tip' } },
        {
          label: 'Playgrounds',
          items: [{ label: 'Anonymous step-up', slug: 'playground/anonymous-step-up', badge: { text: 'New', variant: 'success' } }],
        },
        {
          label: 'Reference',
          items: [
            { label: 'Response format & HTTP status', slug: 'reference/response-format' },
            { label: 'Return codes', slug: 'reference/return-codes' },
            { label: 'Scopes', slug: 'reference/scopes' },
            { label: 'Source values', slug: 'reference/source-values' },
            { label: 'Profile fields', slug: 'reference/profile-fields' },
            { label: 'App deep links', slug: 'reference/deep-links' },
            { label: 'Timeouts & lifetimes', slug: 'reference/timeouts' },
            { label: 'Deprecations', slug: 'reference/deprecations' },
            { label: 'Spec errata', slug: 'reference/errata' },
          ],
        },
        ...openAPISidebarGroups,
      ],
    }),
  ],
})
