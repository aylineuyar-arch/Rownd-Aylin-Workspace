# Rownd - Aylin Workspace

A static, self-contained UI mockup for a proposal-drafting tool (New Draft, Historic Submissions, Proposal Templates, New RFIs, and an Architecture diagram tab). No build step, no backend — it's a single `index.html` styled with Tailwind's CDN build, living in [`Rownd/`](Rownd/).

## Run it locally

```bash
open Rownd/index.html
```

It needs internet access once, to load Tailwind and the Google Fonts it uses from their CDNs. No local server, no install, no build step.

## Live version

Hosted via GitHub Pages, built from `Rownd/` by the workflow at `.github/workflows/pages.yml` on every push to `main`. URL is in this repo's "About" section on GitHub.
