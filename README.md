# Email Verification Tool

Checks email syntax, DNS/MX records, SMTP deliverability, catch-all domain
behavior, disposable/temporary-email status, role-based address detection,
and free-vs-business provider — for a single address or in bulk (CSV/XLSX/TXT),
with a 0–100 confidence score and CSV export.

## What changed vs. the original version

- **Disposable-domain check is now offline by default.** The old version
  called out to two GitHub-hosted lists on *every single email checked* —
  slow, and it breaks silently if GitHub rate-limits or is unreachable. Now
  it uses a bundled offline list (`disposable_domains.py`), with an optional
  manual "refresh from remote" button in the sidebar for when you do have
  internet access.
- **SMTP checks now have real timeouts** and detect **catch-all domains**
  (servers that accept mail for any address, which makes a bare "250 OK"
  meaningless) — the original had neither.
- **Bulk processing is concurrent** (ThreadPoolExecutor) instead of one
  email at a time, with a progress bar and a CSV download button.
- **Fixed the XLSX/TXT bulk tabs**, which previously called `st.dataframe()`
  inside a helper function instead of returning results, so nothing ever
  rendered in the main flow for those formats. Also fixed a crash when a row
  in the uploaded file wasn't a clean string.
- **Added `openpyxl`** to `requirements.txt` — `pandas.read_excel` needs it
  and it was missing, so XLSX uploads would have failed outright.
- **Role-based (`info@`, `admin@`, ...) and free-provider (Gmail, Yahoo, ...)
  detection**, useful for filtering marketing lists.
- **Confidence score (0–100) and verdict** (Valid / Risky / Unknown /
  Invalid) combining all signals, instead of just raw pass/fail flags.
- Replaced the stylesheet's hard-coded Streamlit CSS-hash selectors (which
  break on every Streamlit version bump) with stable `data-testid` selectors.

## Local setup

```bash
pip install -r requirements.txt
streamlit run main.py
```

Or open the folder in the included `.devcontainer` (VS Code / GitHub
Codespaces) — it installs everything and starts Streamlit automatically.

## Important limitations (be upfront about these)

- **SMTP verification is inherently unreliable from cloud hosts.** Most
  free hosting platforms' outbound IPs are widely greylisted/blocked by
  major mail providers (Gmail, Outlook, etc.), so `smtp_deliverable` will
  often come back `None` (inconclusive) rather than a clean True/False.
  That's expected — treat it as a supporting signal, not a certainty.
- The bundled disposable list is a curated few hundred common domains, not
  an exhaustive registry — new burner-email services appear constantly.
- Real-time SMTP probing can be treated as spam-like activity by some mail
  servers; keep the "max rows" cap on bulk runs conservative on shared/free
  infrastructure.

## Free deployment options

All of these have a free tier suitable for a Streamlit app like this:

1. **Streamlit Community Cloud** (streamlit.io/cloud) — purpose-built for
   Streamlit apps, free tier, deploys directly from a public GitHub repo,
   zero server config. Easiest option for this specific project.
2. **Hugging Face Spaces** (huggingface.co/spaces) — free CPU tier, has a
   native Streamlit SDK option, good uptime, easy GitHub sync.
3. **Render** (render.com) — free web service tier (spins down when idle,
   spins back up on request); works with any `requirements.txt` + start
   command (`streamlit run main.py --server.port $PORT --server.address 0.0.0.0`).
4. **Railway** (railway.app) — usage-based free starter credit each month;
   simple GitHub deploy, good for demos.
5. **Fly.io** — free allowance covers small always-on apps; more setup
   (needs a `Dockerfile`/`fly.toml`) but no idle spin-down like Render's
   free tier.

For a quick clone-and-share demo, Streamlit Community Cloud or Hugging Face
Spaces will get you running fastest with the least configuration.
