# Private RFI/RFP archive — local only

Drop previously-sent RFI/RFP files here. This folder's contents are highly
sensitive and are meant to be the basis for future generated proposals —
but they must never leave this machine.

- Everything in this folder except this file and `.gitkeep` is excluded by
  `.gitignore` at the repo root. `git status` / `git add -A` will not pick
  these files up, and they will never be pushed to the (public) GitHub repo.
- The New Draft Console only lists/previews these files when you run the
  site locally (`python3 serve_no_cache.py` from inside `Rownd/`). On the
  deployed GitHub Pages site this folder doesn't exist, so the listing
  shows an empty/unavailable state there instead — that's expected, not a
  bug.
