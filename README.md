# Farhan's Way

Workout tracker for Farhan and his clients. Works on Android and iPhone from the home screen, no app store needed.

| Part | Where it lives |
|---|---|
| The app (this repo) | Netlify (updates itself every time this repo changes) |
| Clients, programs, workouts | Supabase database |

## Files
- `index.html` – the whole app
- `manifest.webmanifest`, `sw.js`, `icons/` – lets people "Add to Home Screen"
- `supabase/setup.sql` – creates the database tables and security rules (run once)

## One-time setup
1. **Supabase** → SQL Editor → New query → paste all of `supabase/setup.sql` → Run. It should say "Success".
2. **Netlify** → Add new site → Import from GitHub → pick this repo → Deploy (no build settings needed).
3. Open the Netlify link, choose **Trainer**, sign in with `admin` / `1235813` and set a private password straight away.
4. Add clients under **Clients → Add client**. Their ID is their mobile number and their first password is `admin`; the app makes them choose a new one.

## Updating the app
Change a file in this repo → Netlify republishes in about a minute. Phones pick up the new version the next time the app is opened.

## Keys
`index.html` contains the Supabase **publishable** key. That is meant to be public. Never put the `secret` / `service_role` key or the database password in this repo.
