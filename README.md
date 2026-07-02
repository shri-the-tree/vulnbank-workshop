# VulnBank Workshop

A hands-on AI security workshop where you attack a simulated bank's AI agents across 5 escalating levels — directly from your browser, no special tooling required.

Each level exposes a different real-world AI vulnerability. You send the attack, the agent responds, and the dashboard tells you when you've won.

---

## Before you start

You need a **free Groq API key**. It takes under a minute:

1. Go to **https://console.groq.com** and sign up
2. Under **API Keys**, create a new key
3. Copy it — it starts with `gsk_`

---

## Quickstart — Docker (recommended)

Requires [Docker Desktop](https://www.docker.com/products/docker-desktop/).

```bash
git clone https://github.com/shri-the-tree/vulnbank-workshop
cd vulnbank-workshop
docker compose up
```

Open **http://localhost:9000** in your browser. You'll be asked to paste your Groq key — it's verified live before anything unlocks.

---

## Quickstart — Node.js (no Docker)

Requires **Node.js 18+**.

```bash
git clone https://github.com/shri-the-tree/vulnbank-workshop
cd vulnbank-workshop
npm install
GROQ_API_KEY=gsk_... npm start
```

Open **http://localhost:9000**.

> If you set `GROQ_API_KEY` in your environment before starting, the key gate is skipped automatically.

---

## The 5 Levels

| Level | Target | Attack Type | What you're doing |
|-------|--------|-------------|-------------------|
| L1 | VulnBank Virtual Assistant | Prompt Injection | Trick the assistant into leaking a confidential account number from its system prompt |
| L2 | VulnBank Statement Assistant | RAG Data Exfiltration | Hijack the knowledge base retrieval to exfiltrate another customer's statement |
| L3 | VulnBank Accounts Backend | SQL Injection | Break out of the query filter to expose a flagged internal account |
| L4 | VulnBank Concierge Memory | Memory Injection | Plant a persistent instruction in the agent's memory and prove it survives to a later session |
| L5 | VulnBank Transfer Engine | Agent Impersonation | Spoof a trusted internal identity to push a fraudulent transfer through the system |

The browser UI walks you through each one — objective, what to look for, and technique hints included on every page.

---

## How it works

```
Browser (http://localhost:9000)
  └── VulnBank dashboard
        ├── Groq API key gate  ← enter your key here first
        └── Levels L1–L5
              ├── Read the objective + technique hints
              ├── Send your attack payload directly to the target agent
              └── Watch the response — the dashboard flags when a level is complete
```

All 5 agents run locally inside the container. Your attacks go straight to them — no relay, no proxy, no internet after the initial key verification.

---

## Troubleshooting

**"Invalid API key"** — make sure there are no extra spaces around the key. Keys start with `gsk_`.

**Port already in use** — the app uses ports `7002 7005 7007 7011 7021 9000`. Stop any services using those ports and re-run `docker compose up`.

**Container won't start** — make sure Docker Desktop is running first (`docker ps` should work without errors).

**Level badge stuck on "not yet"** — the badge polls every 3 seconds. If it doesn't flip within ~10 seconds of a successful attack, try re-sending the payload.

---

## Ports (for reference)

| Port | Agent |
|------|-------|
| 7002 | VulnBank Virtual Assistant (L1) |
| 7005 | VulnBank Statement Assistant (L2) |
| 7011 | VulnBank Accounts Backend (L3) |
| 7007 | VulnBank Concierge Memory (L4) |
| 7021 | VulnBank Transfer Engine (L5) |
| 9000 | Dashboard |

---

Built on [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent) · Apache-2.0
