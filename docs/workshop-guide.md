# VulnBank Workshop — Participant Guide

> **How to use this guide**
> Read it top to bottom before the session starts, or upload it to Claude / ChatGPT / Gemini and ask it questions as you go. Every section is self-contained.

---

## Section 1 — Setup & Installation

### What you're setting up

VulnBank is a simulated bank running entirely on your laptop. It has five AI agents, each with a different security vulnerability built in. You will attack them directly from your browser — no cloud accounts, no special hacking tools, nothing to install beyond what's listed below.

The whole thing runs offline after the initial setup. Your attack payloads never leave your machine (except for the LLM call to Groq, which is just the normal API call the agent would make anyway).

---

### What you need before you start

| Requirement | Why | Where to get it |
|---|---|---|
| A laptop running Windows, macOS, or Linux | The app runs locally | — |
| Docker Desktop **or** Node.js 18+ | To run the app | See below |
| A free Groq API key | The agents use Groq's LLM API | https://console.groq.com |
| A modern browser (Chrome, Firefox, Edge) | The attack UI runs in the browser | — |

You only need **one** of Docker or Node.js — pick whichever you already have.

---

### Step 1 — Get your Groq API key

Groq provides free API access to open-source LLMs (Llama 3.3, etc.). The agents in VulnBank use it as their brain.

1. Go to **https://console.groq.com** and sign up (Google/GitHub login works)
2. Once logged in, click **API Keys** in the left sidebar
3. Click **Create API Key**, give it any name (e.g. `vulnbank-workshop`)
4. Copy the key — it starts with `gsk_` and is shown only once
5. Paste it somewhere safe (Notepad, Notes app) — you'll need it in Step 3

> **Free tier limits**: Groq's free tier allows ~14,400 requests/day per key, which is more than enough for this workshop. You will not be charged.

---

### Step 2 — Get the app

Open a terminal (Command Prompt, PowerShell, or Terminal on Mac/Linux) and run:

```bash
git clone https://github.com/shri-the-tree/vulnbank-workshop
cd vulnbank-workshop
```

If you don't have Git installed, download it from **https://git-scm.com/downloads** first.

Alternatively, you can download a ZIP from the GitHub page (click **Code → Download ZIP**), extract it, and open a terminal inside the extracted folder.

---

### Step 3 — Start the app

#### Option A — Docker (recommended)

Docker runs the app in an isolated container. Nothing gets installed on your system beyond the container itself.

1. Install Docker Desktop if you don't have it: **https://www.docker.com/products/docker-desktop**
2. Open Docker Desktop and wait for it to finish starting (the whale icon in your taskbar/menu bar stops animating)
3. In your terminal, inside the `vulnbank-workshop` folder, run:

```bash
docker compose up
```

The first run downloads the pre-built image (~150 MB) and starts all five agents. This takes about 30–60 seconds. You'll see log lines appearing — that's normal.

When you see output like this, everything is up:

```
dvaa  | [dashboard] listening on http://localhost:9000
dvaa  | [helperbot]  listening on port 7002
dvaa  | [ragbot]     listening on port 7005
dvaa  | [databot]    listening on port 7011
dvaa  | [memorybot]  listening on port 7007
dvaa  | [worker-1]   listening on port 7021
```

4. Open **http://localhost:9000** in your browser

#### Option B — Node.js (no Docker)

If you have Node.js 18 or higher installed:

```bash
npm install
npm start
```

Then open **http://localhost:9000** in your browser.

To check your Node.js version: `node --version`. If it's below 18, download the latest from **https://nodejs.org**.

---

### Step 4 — Enter your Groq API key

When you open `http://localhost:9000`, you'll land on a key verification screen.

1. Paste your Groq API key (the `gsk_...` string from Step 1) into the input field
2. Click **Verify & Continue**
3. The app makes a live test call to Groq to confirm the key works — this takes 2–3 seconds
4. If valid, you'll proceed directly to the workshop levels

> If you see **"Invalid API key"**: double-check that you copied the full key with no extra spaces. Keys are long (~56 characters).

> If you see a **network error**: check your internet connection. The key verification is the only step that requires internet — everything else runs locally.

---

### Step 5 — Confirm everything is working

Once past the key screen, you should see the **VulnBank dashboard** with five levels listed (L1 through L5), each showing:

- The level name and attack type
- An **Objective** section (what you need to do)
- A **What to look for** section (how you know you've succeeded)
- A **Technique** section (a concrete nudge in the right direction)
- An attack form at the bottom where you send your payload

If all five levels are visible, you're ready. You do not need to do anything else before the workshop begins.

---

### Stopping and restarting

**To stop**: press `Ctrl + C` in the terminal where the app is running. For Docker, you can also run `docker compose down`.

**To restart**: run `docker compose up` again (Docker) or `npm start` (Node.js). The app starts fresh each time — canary tokens regenerate, level completion status resets.

**To update** (if a new version is released during the workshop):

```bash
# Docker
docker compose pull
docker compose up

# Node.js
git pull
npm start
```

---

### Port reference

The app uses these ports on your localhost. If any are already in use by another application, you'll see a startup error.

| Port | What it is |
|------|-----------|
| 9000 | VulnBank dashboard (open this in your browser) |
| 7002 | L1 — VulnBank Virtual Assistant |
| 7005 | L2 — VulnBank Statement Assistant |
| 7011 | L3 — VulnBank Accounts Backend |
| 7007 | L4 — VulnBank Concierge Memory |
| 7021 | L5 — VulnBank Transfer Engine |

If you hit a port conflict, stop whatever is using the port and restart the app.

---

### Common setup problems

| Problem | Likely cause | Fix |
|---|---|---|
| `docker compose up` says "Cannot connect to the Docker daemon" | Docker Desktop isn't running | Open Docker Desktop and wait for it to fully start, then retry |
| Port already in use (e.g. `EADDRINUSE 9000`) | Another app is on that port | Find and stop that app, or restart your computer |
| "Invalid API key" after pasting the key | Wrong key or extra whitespace | Re-copy the key directly from the Groq console, no surrounding spaces |
| Browser shows "This site can't be reached" | App hasn't finished starting | Wait for the terminal to show all agents listening, then refresh |
| `npm install` fails | Node.js version too old | Run `node --version` — upgrade to 18+ if below |
| Levels all show "not yet" and never flip | Level detection polling | Wait up to 10 seconds after a successful attack; the badge polls every 3 seconds |

---

*Next: Section 2 — Understanding the Levels*
