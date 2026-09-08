# trustgraph

**Interpersonal Risk & Trust Vault** — a privacy-first CLI for quantifying,
tracking, and visualizing interpersonal trust over time.

Trust is tracked as a **time series**, not a static snapshot. Every interaction is a
timestamped event, and the trust score is the trajectory produced by folding those
events together.

## Features
- ABI dimensions (Ability, Benevolence, Integrity) with a Dark Triad risk penalty
- Time-series trust score (EMA learning rule) with trend, volatility, and incident impact
- Inline terminal chart of the trust trajectory
- Encrypted vault (PBKDF2-HMAC-SHA256 → Fernet/AES)

## Install

```bash
pip install -r requirements.txt
```

## Run

```bash
python app.py
```

- First run: creates a new vault with sample data and asks for a master password (min 8 chars).
- Later runs: prompts for that password to decrypt the vault.

## Commands

| Command | Description |
|---|---|
| `list` / `ls [query]` | List profiles with their time-series trust score |
| `view` / `v <id/name>` | Full detail: chart, metrics, event timeline |
| `plot` / `chart <id/name>` | Show just the trust time-series chart |
| `add` / `a` | Add a new profile |
| `edit` / `e <id/name>` | Edit a profile (adds a reassessment event) |
| `log` / `incident <id/name>` | Log a negative event |
| `favor` / `good <id/name>` | Log a positive event |
| `analyze` / `summary` | Portfolio risk summary |
| `export` / `backup` | Export an encrypted backup |
| `help` / `?` | Show all commands |
| `quit` / `exit` / `q` | Save, encrypt, and exit |

## Security

- The vault is encrypted with Fernet using a key derived from your master password via
  PBKDF2-HMAC-SHA256 (200,000 iterations) and a random 16-byte salt.
- Plaintext is never written to disk; decryption happens in memory only.
- `vault.enc` and `vault.salt` are git-ignored — never commit them.

## Trust model

- **Ability / Benevolence / Integrity** — Mayer, Davis & Schoorman (1995).
- **Dark Triad risk penalty** — Paulhus & Williams (2002).
- **Reciprocity** — Gouldner (1960); Blau (1964).
- **Trust dynamics** — Marsh (1994); Jonker & Treur (1999):
  `T(t) = T(t-1) + α·(E(t) - T(t-1))`.
