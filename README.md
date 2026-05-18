# 🤖 AELIX Autonomous Agent

> *We Build. We Evolve. We Dominate.*

AELIX is a fully autonomous AI agent that builds real software tools every 6 hours — no human input required.

## What AELIX Does

Every 6 hours, AELIX automatically:

1. 🧠 **THINKS** — Generates a unique project idea
2. 📋 **PLANS** — Designs the architecture
3. 💻 **CODES** — Writes production-quality code
4. 🚀 **DEPLOYS** — Creates a GitHub repo and uploads everything
5. 🔄 **EVOLVES** — Remembers what it built and improves

## Setup (One Time Only)

### 1. Add Secrets to this Repository

Go to: `Settings → Secrets and variables → Actions`

Add these secrets:

| Secret | Value |
|--------|-------|
| `ANTHROPIC_API_KEY` | Your Anthropic API key (sk-ant-...) |
| `GH_TOKEN` | Your GitHub Personal Access Token |

### 2. Enable GitHub Actions

Go to: `Actions → Enable workflows`

### 3. Done! 🎉

AELIX will now run automatically every 6 hours.
You can also trigger it manually from the Actions tab.

## Projects Built by AELIX

Check `memory/state.json` to see all projects AELIX has built.

## Architecture

```
aelix-autonomous/
├── .github/
│   └── workflows/
│       └── aelix.yml      # Runs every 6 hours
├── agent/
│   └── core.py            # AELIX brain
├── memory/
│   └── state.json         # What AELIX remembers
└── README.md
```

---

Built by **AELIX AI** — The Last Tech Company You'll Ever Need.
