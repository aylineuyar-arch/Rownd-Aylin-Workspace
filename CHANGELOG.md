# Changelog

Every push to this repo is logged here, newest first, in plain language — what changed and why. This file is updated as part of every commit from now on, not just written after the fact.

## 2026-09-05

- **Q&A Guidance moved next to Extracted Topic Info, plus a real summary sentence and per-item truncation** — was stacked below Extracted Topic Info; now sits side by side with it (sidebar widened to a two-column grid so both are visible without scrolling past one another). Added a plain-language summary line at the top of the box (e.g. "4 questions were asked, mostly about Eligibility / Admin. 3 answers read as binding: ..."), generated from the same category/keyword scoring already in place — not a new analysis, just a rollup of it. To cut down on visual noise, each answer over 110 characters is now truncated in the list with a "View full answer" toggle; nothing is removed or hidden permanently — the full text is always one click away, and every question still appears (per the prior "do not exclude any questions" fix). Verified via a synthetic long answer (111 chars truncated → 444 chars on expand → back to 111 on collapse) since the real sample text's answers all happened to be under the threshold.

- **Fix: Q&A Guidance was excluding a question** (`e046b30` follow-up) — the "Key guidance" box only showed answers matching a binding-language keyword check, which silently left out questions that didn't happen to match (including one about citizenship/ITAR eligibility — clearly important, just phrased differently). Removed the filtered subset entirely. All parsed questions now always appear in one list; a "⚠ binding language" flag is added inline to items that match, but nothing is ever left out.

- **`e046b30`** — Add Q&A Guidance box. Parses Q&A pairs pasted into the Q&A answers checklist item, tags each by type (Eligibility/Admin, Pricing/Cost, Phase/Scope, Technical) via keyword scoring, and shows the tally as a headline metric. New box sits in the sidebar below Extracted Topic Info. Caught and fixed a real bug during testing: "strict" was substring-matching inside "restrictions" (plain `indexOf`), wrongly flagging an unrelated answer — switched to word-boundary regex matching.

- **`d055e3c`** — Made Objective / Description / Phase I / Phase II collapsible in the sidebar (same chevron-toggle pattern as Trend Insights elsewhere), collapsed by default, since those are the longest text blocks on the page. Badges and tags stay always-visible.

- **`59e9827`** — Complete rework of RFI extraction around the real DoD SBIR/STTR topic-listing format (matching the actual public topics API schema — topicCode, topicTitle, cmmcLevel, technologyAreas, keywords, objective, description, phase1/2/3Description — as a deliberate future swap-in point; the live API is still not connected). Adds a release-status badge (OPEN/PRE-RELEASE/CLOSED), a phase-applicability badge (e.g. "Direct to Phase II — Phase I proposals rejected"), and renders Technology Areas / Modernization Priorities / Keywords as separate tag chips instead of one paragraph. Parsed sections route into the matching checklist box by meaning instead of one text dump. Same parser now also runs on manual paste, not just PDF upload. Found and fixed a regex bug where "PRE-RELEASE" was truncated to "PRE" because its own internal hyphen was mistaken for the status/title separator.

- **`3d4447f`** — Real client-side PDF parsing via PDF.js (loaded from cdnjs), replacing the earlier mock. Page count is exact; due date and formatting are regex pattern-matches over the real extracted text; instructions/rules sections are picked by keyword-scoring. Non-PDF uploads are rejected with a clear message; a corrupt PDF surfaces PDF.js's real error instead of failing silently.

- **`14280f9`** — Added "Drafts in Progress" nav section for resuming work. Added a "Proposal name" field to the New Draft topic card and a "Save Draft" button that builds a real row (topic + proposal name + live checklist progress), not a static mock. "Resume" reloads that topic into New Draft.

- **`6ee2f33`** — New Draft became a two-column layout: existing content on the left, a new sticky "Extracted from PDF" sidebar on the right. First version of PDF-upload-triggered extraction (mock at this point, made real two commits later).

- **`65b611a`**, **`5d35f36`**, **`3e32b72`** — Three rounds of text-size increases after feedback that the UI text was too small, especially the header. Final state: h1 headings 24px→48px, header wordmark 20px→30px, nav bubbles 16px text with tripled padding, body/buttons 16px→18px. Also reordered nav (New RFIs moved to second position, right after New Draft).

- **`7b68d6e`** — Page was using a fixed 1024px-wide content column regardless of window size (49% of a 2091px-wide window). Switched to a fluid width (95%, capped at 1600px) — measured directly on a live browser tab: 1024px→1600px, side margins 533px→245px. Also added the "Reference Documents" nav section (muted brown) for general reference material, kept separate from Historic Submissions' win/loss-tracked history.

- **`9696e33`** — Added a file-upload dropzone to the RFI details checklist item (uploading also checks the item off). Made checklist completion fully non-blocking — nothing requires any box filled before generating. Added an explicit "Generate Draft" button; the draft panel now starts hidden and only appears once clicked, instead of always showing a pre-filled draft.

- **`d0d54c5`** — Replaced the vague freeform "Manual" entry textarea in New RFIs with explicit Title and Topic Number fields, plus a "Use for new draft" button that enables once both are filled.

- **`501e018`** — Two real bugs: (1) the draft text was capped to a narrower width than the card around it, leaving a lopsided empty gap; removed the cap. (2) No explicit UTF-8 charset declaration in the file meant em dashes, middle dots, and icons rendered as mojibake on any host that didn't supply its own charset header — including the "open index.html locally" instructions given earlier. Added `<meta charset="UTF-8">` directly to the file so it's correct everywhere.

- **`7943820`** — Moved "RFI details" from a standalone card at the top of the page into the Draft Checklist as its first item, per follow-up clarification.

- **`d2b8119`** — Removed the Proposal Templates section entirely. Added the Draft Checklist with paste-in fields for solicitation instructions, rules/component list, and Q&A answers (auto-checking indicators, progress counter). Widened the main content column and fixed a checklist textarea/label alignment bug.

## 2026-09-02

- **`b1c3ab0`** — Replaced a corner "+" icon (whose tooltip didn't show on hover, since `title` attributes on `disabled` buttons are often suppressed by the browser) with a plainly labeled "+ Comments (tentative)" button next to "Improve selection".

- **`b7d1346`** — Moved the tentative "add comments" marker from the Architecture diagram (where it was mistakenly placed) to the actual New Draft panel, where the feature was actually meant to live.

- **`33fa93e`** — Marked the "comments/recommendations" idea as tentative — dashed styling, not a built feature — initially placed on the Architecture diagram.

- **`fb1ee2b`** — Added numbered bubbles directly onto the architecture diagram's boxes, matching the numbered step-by-step list below it, so the diagram and the list cross-reference each other.

- **`57b536b`** — Replaced the architecture page's dense prose paragraph with a numbered 1–6 step-by-step list (colored bubbles matching the diagram's own color language), plus a 7th "tentative" step for the optional Topic Poller.

- **`cfd663a`** — Added a dashed, clearly-marked "Topic Poller" box to the side of the architecture diagram — a tentative/proposed addition (scheduled polling of the DoD SBIR/STTR feed), not built, visually distinct (dashed border, muted color, "TENTATIVE" tag) from the real architecture.

- **`b36a727`** — Moved the mockup from the repo root into a `Rownd/` folder and switched GitHub Pages from simple branch-based hosting to a GitHub Actions build (`.github/workflows/pages.yml`), since Pages can only serve a plain branch from the root or `/docs`, and the file needed to live in a named subfolder.

- **`bcd116e`** — Added the `Rownd/` folder structure (initially just a placeholder, before the mockup moved into it).

- **`ca05219`** — Initial commit: the Draft Console UI mockup, plus repo README.
