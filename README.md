# The Better Daily Life

The website for **thebetterdailylife.com** — an initiative for getting 1% better every day through continuous learning. Includes a podcast section, a newsletter section, and a free **Financial Education** hub (Google sign-in + interactive money tools).

## Files
```
index.html            ← the whole website (one file)
functions/subscribe.js ← serverless function: subscribes Google sign-ins to Beehiiv
README.md
```

## Hosting
Deployed free on **Cloudflare Pages** (connected to this GitHub repo). Every commit
auto-deploys in about a minute.

## Setup
See **SETUP-GUIDE** for click-by-click instructions: deploying, connecting the domain,
turning on Google sign-in, and wiring up the Beehiiv newsletter.

## What you edit
- `index.html` → paste your **Google Client ID**, your **Buzzsprout** player embed, and your **Beehiiv** signup embed (all clearly marked with comments).
- Cloudflare dashboard → environment variables for the secret **Beehiiv API key**.

## Note
Financial figures are educational estimates using virtual money and steady average
returns to illustrate compounding. Real investments rise and fall and can lose value.
For learning only — not financial advice.
