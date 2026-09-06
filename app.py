"""
Interpersonal Risk & Trust Vault (CLI)
=======================================
A privacy-first command-line application for quantifying, tracking and
visualizing interpersonal trust over time.

Cross-platform: runs on Linux and Windows (Python + `cryptography` + `rich`).

TIME SERIES IS THE ROOT OF ANALYSIS
-----------------------------------
People change over time, and that change is what matters. Every meaningful
interaction is recorded as a timestamped *event*, and the trust score is the
trajectory produced by folding those events together - not a static snapshot.

SECURITY MODEL
--------------
* Master password -> PBKDF2-HMAC-SHA256 (200,000 iterations) -> Fernet key.
* A random 16-byte salt is generated once and stored in `vault.salt`.
* All vault data is serialized to JSON and AES-encrypted (Fernet) in memory
  before being written atomically to `vault.enc`. Plaintext is NEVER persisted.
* Decryption happens in memory only; a wrong password produces an
  InvalidToken exception which is caught and causes a clean exit.

TRUST MODEL (research-grounded)
-------------------------------
1. Trustworthiness dimensions (Ability, Benevolence, Integrity):
   Mayer, R. C., Davis, J. H., & Schoorman, F. D. (1995). An integrative model
   of organizational trust. Academy of Management Review, 20(3), 709-734.

2. Risk penalty (Dark Triad):
   Paulhus, D. L., & Williams, K. M. (2002). The Dark Triad of personality.
   Journal of Research in Personality, 36(6), 556-563.

3. Reciprocity (social exchange):
   Gouldner, A. W. (1960). The norm of reciprocity. American Sociological Review.
   Blau, P. M. (1964). Exchange and Power in Social Life. Wiley.

4. Trust dynamics over time:
   Marsh, S. (1994). Formalising Trust as a Computational Concept. PhD thesis.
   Jonker, C. M., & Treur, J. (1999). Formal analysis of models for the
   dynamics of trust based on experiences.
   -> Trust updates from each experience: T(t) = T(t-1) + a * (E(t) - T(t-1)).
"""

import os
import sys
import json
import math
import time
import uuid
import base64
import getpass
from datetime import datetime

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
APP_NAME = "Interpersonal Risk & Trust Vault"
VAULT_FILE = "vault.enc"
SALT_FILE = "vault.salt"
BACKUP_SUFFIX = ".enc"

PBKDF2_ITERATIONS = 200_000
SALT_LENGTH = 16
KEY_LENGTH = 32

EMA_ALPHA = 0.4                   # learning rate (Jonker & Treur 1999)
NEUTRAL_TRUST = 50.0              # prior trust before any experience
INCIDENT_HALF_LIFE_DAYS = 30.0    # exponential decay for incident weighting
VELOCITY_WINDOW_DAYS = 30.0       # recent window for trend / volatility
VELOCITY_CHANGE_THRESHOLD = 0.15  # pts/day beyond which trust is changing
HISTORY_CAP = 2000

SAFE_THRESHOLD = 67
CAUTION_THRESHOLD = 34

COLOR_SAFE = "#2ecc71"
COLOR_CAUTION = "#f1c40f"
COLOR_HIGH_RISK = "#e74c3c"

DARK_TRIAD_LEVELS = ["Low Risk", "Moderate Risk", "High Risk - Machiavellian", "Extreme Threat"]
RISK_PENALTIES = {
    "Low Risk": 0,
    "Moderate Risk": 15,
    "High Risk - Machiavellian": 30,
    "Extreme Threat": 50,
}
RECIPROCITY_LEVELS = ["Synergistic", "Transactional", "Parasitic"]
BOUNDARY_STRATEGIES = ["Fully Trust", "Transactional Only", "Low-Information Diet", "Cut Off"]
CATEGORIES = ["Work", "Friend", "Family", "Business"]

# severity / magnitude -> the trustworthiness value the event implies (0-100)
INCIDENT_VALUES = {1: 40, 2: 25, 3: 10}
FAVOR_VALUES = {1: 60, 2: 75, 3: 90}

EVENT_MARKERS = {"assessment": "\u25cf", "incident": "\u25bc", "favor": "\u25b2"}

console = Console(width=100)
# ---------------------------------------------------------------------------
# Security & key management
# ---------------------------------------------------------------------------
def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte Fernet key from the master password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def load_or_create_salt() -> bytes:
    """Return the salt, generating and persisting it on first startup."""
    if os.path.exists(SALT_FILE):
        try:
            with open(SALT_FILE, "rb") as fh:
                salt = fh.read()
            if len(salt) == SALT_LENGTH:
                return salt
        except OSError:
            pass
    salt = os.urandom(SALT_LENGTH)
    with open(SALT_FILE, "wb") as fh:
        fh.write(salt)
    return salt


def encrypt_vault(data, key: bytes) -> None:
    """Serialize `data` to JSON, encrypt it, and write atomically."""
    f = Fernet(key)
    plaintext = json.dumps(data, indent=2).encode("utf-8")
    ciphertext = f.encrypt(plaintext)
    tmp = VAULT_FILE + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(ciphertext)
    os.replace(tmp, VAULT_FILE)


def decrypt_vault(key: bytes):
    """Decrypt and parse the vault in memory. Raises on wrong key/corruption."""
    f = Fernet(key)
    with open(VAULT_FILE, "rb") as fh:
        ciphertext = fh.read()
    plaintext = f.decrypt(ciphertext)
    data = json.loads(plaintext.decode("utf-8"))
    if not isinstance(data, dict) or "profiles" not in data:
        raise ValueError("Vault structure is invalid (possible corruption).")
    return data


# ---------------------------------------------------------------------------
# Trust scoring (time series at the root)
# ---------------------------------------------------------------------------
def compute_raw_trust_score(profile) -> float:
    """Static ABI + risk assessment (the 'current assessment' reference)."""
    base = ((profile["benevolence"] + profile["integrity"] + profile["ability"]) / 30.0) * 100.0
    penalty = RISK_PENALTIES.get(profile.get("dark_triad_risk", "Low Risk"), 0)
    return max(0.0, min(100.0, base - penalty))


def score_band(score: float):
    """Map a trust score to a (label, color) risk band."""
    if score >= SAFE_THRESHOLD:
        return "Safe", COLOR_SAFE
    if score >= CAUTION_THRESHOLD:
        return "Caution", COLOR_CAUTION
    return "High Risk", COLOR_HIGH_RISK


def append_event(profile, kind, value, note=""):
    """Append a timestamped event to a profile's time series (the root)."""
    ev = {"ts": time.time(), "kind": kind,
          "value": max(0.0, min(100.0, float(value))), "note": note}
    events = profile.setdefault("events", [])
    events.append(ev)
    if len(events) > HISTORY_CAP:
        del events[: len(events) - HISTORY_CAP]
    return ev


def compute_trust_series(profile, alpha=EMA_ALPHA):
    """Fold the event series with the EMA learning rule.

    T(t) = T(t-1) + alpha * (E(t) - T(t-1)),  T(0) = NEUTRAL_TRUST.
    Returns [(ts, trust, event_or_None)] in chronological order. The current
    trust score is the last point of this series.
    """
    events = sorted(profile.get("events", []), key=lambda e: e["ts"])
    if not events:
        return [(time.time(), compute_raw_trust_score(profile), None)]
    series = [(events[0]["ts"], events[0]["value"], events[0])]
    t = events[0]["value"]
    for e in events[1:]:
        t = t + alpha * (e["value"] - t)
        series.append((e["ts"], t, e))
    return series


def current_trust(profile) -> float:
    """The headline trust score: the head of the time series."""
    return compute_trust_series(profile)[-1][1]


def linear_slope(xs, ys) -> float:
    n = len(xs)
    if n < 2:
        return 0.0
    mx = sum(xs) / n
    my = sum(ys) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    den = sum((x - mx) ** 2 for x in xs)
    if den == 0:
        return 0.0
    return num / den


def _recent_series(profile, window_days=VELOCITY_WINDOW_DAYS):
    series = compute_trust_series(profile)
    if not series:
        return []
    cutoff = series[-1][0] - window_days * 86400.0
    recent = [(ts, t) for ts, t, _ in series if ts >= cutoff]
    return recent if len(recent) >= 2 else [(ts, t) for ts, t, _ in series]


def trust_velocity(profile, window_days=VELOCITY_WINDOW_DAYS) -> float:
    """Slope of the trust series over the recent window (points/day)."""
    recent = _recent_series(profile, window_days)
    if len(recent) < 2:
        return 0.0
    t0 = recent[0][0]
    xs = [(ts - t0) / 86400.0 for ts, _ in recent]
    ys = [t for _, t in recent]
    return linear_slope(xs, ys)


def trust_volatility(profile, window_days=VELOCITY_WINDOW_DAYS) -> float:
    """Std dev of trust changes over the recent window (instability)."""
    recent = _recent_series(profile, window_days)
    if len(recent) < 2:
        return 0.0
    ys = [t for _, t in recent]
    diffs = [ys[i + 1] - ys[i] for i in range(len(ys) - 1)]
    m = sum(diffs) / len(diffs)
    return math.sqrt(sum((d - m) ** 2 for d in diffs) / len(diffs))


def total_change(profile) -> float:
    """Total trust change from first observation to now."""
    series = compute_trust_series(profile)
    if len(series) < 2:
        return 0.0
    return series[-1][1] - series[0][1]


def incident_impact(profile, now=None, half_life_days=INCIDENT_HALF_LIFE_DAYS) -> float:
    """Recency-weighted count of incident events (exponential half-life decay)."""
    now = now if now is not None else time.time()
    lam = math.log(2.0) / half_life_days
    return sum(math.exp(-lam * max(0.0, (now - e["ts"]) / 86400.0))
               for e in profile.get("events", []) if e.get("kind") == "incident")
# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
def new_profile(name: str = "New Person") -> dict:
    return {
        "id": str(uuid.uuid4()),
        "name": name,
        "category": "Friend",
        "benevolence": 5,
        "integrity": 5,
        "ability": 5,
        "dark_triad_risk": "Low Risk",
        "reciprocity": "Synergistic",
        "boundary_strategy": "Fully Trust",
        "events": [],
        "created_at": time.time(),
        "updated_at": time.time(),
    }


def recommendation(profile, score: float) -> str:
    """Human-readable safety guidance derived from the time-series score."""
    band, _ = score_band(score)
    parts = []
    if band == "Safe":
        parts.append("High trust - the relationship appears reliable and low-risk.")
    elif band == "Caution":
        parts.append("Moderate trust - verify key interactions and stay observant.")
    else:
        parts.append("High risk - minimize exposure; consider protective boundaries.")

    vel = trust_velocity(profile)
    if vel < -VELOCITY_CHANGE_THRESHOLD:
        parts.append("Trust is currently deteriorating.")
    elif vel > VELOCITY_CHANGE_THRESHOLD:
        parts.append("Trust is currently improving.")

    if profile["reciprocity"] == "Parasitic":
        parts.append("Parasitic exchange detected - a strong red flag.")
    elif profile["reciprocity"] == "Transactional":
        parts.append("Transactional reciprocity - keep expectations explicit.")
    else:
        parts.append("Synergistic reciprocity - balanced mutual benefit.")

    parts.append(f"Suggested boundary strategy: {profile['boundary_strategy']}.")

    impact = incident_impact(profile)
    if impact >= 3.0:
        parts.append("Multiple recent red flags logged - treat with heightened caution.")
    elif impact >= 1.0:
        parts.append("Recent incident(s) logged.")
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Sample data (demo / testing)
# ---------------------------------------------------------------------------
def _ev(days_ago, kind, value, note=""):
    """Build a sample event `days_ago` in the past."""
    return {"ts": time.time() - days_ago * 86400.0, "kind": kind, "value": value, "note": note}


def _sample(name, category, benevolence, integrity, ability, risk, reciprocity,
            boundary, events):
    p = new_profile(name)
    p["category"] = category
    p["benevolence"] = benevolence
    p["integrity"] = integrity
    p["ability"] = ability
    p["dark_triad_risk"] = risk
    p["reciprocity"] = reciprocity
    p["boundary_strategy"] = boundary
    p["events"] = events
    return p


def sample_profiles():
    """Representative demo profiles with event histories showing change over time."""
    return [
        _sample("Alice Chen", "Work", 9, 9, 8, "Low Risk", "Synergistic", "Fully Trust", [
            _ev(120, "assessment", 60, "First impression"),
            _ev(90, "assessment", 68, "Solid quarter, dependable"),
            _ev(60, "favor", 80, "Helped with a tough project unprompted"),
            _ev(30, "assessment", 84, "Consistent and honest"),
            _ev(10, "favor", 90, "Gave difficult but honest feedback"),
        ]),
        _sample("Marcus Reid", "Friend", 8, 8, 7, "Low Risk", "Synergistic", "Fully Trust", [
            _ev(100, "assessment", 70, "Known him for years"),
            _ev(60, "assessment", 74, "Reliable in a pinch"),
            _ev(30, "assessment", 76, "Steady and consistent"),
        ]),
        _sample("Priya Nair", "Friend", 5, 6, 4, "Moderate Risk", "Transactional", "Transactional Only", [
            _ev(90, "assessment", 55, "Friendly but vague"),
            _ev(40, "incident", 40, "Asked for a large loan, vague about repayment"),
            _ev(20, "incident", 25, "Cancelled plans last minute without notice"),
            _ev(5, "assessment", 35, "Lowered expectations"),
        ]),
        _sample("Dana Kowalski", "Business", 6, 7, 8, "Moderate Risk", "Transactional", "Transactional Only", [
            _ev(80, "assessment", 44, "New business contact"),
            _ev(40, "incident", 40, "Renegotiated terms unilaterally mid-deal"),
            _ev(20, "assessment", 52, "Improved communication"),
            _ev(10, "assessment", 55, "Delivered on revised terms"),
        ]),
        _sample("Victor Moreau", "Business", 4, 3, 6, "High Risk - Machiavellian", "Parasitic", "Low-Information Diet", [
            _ev(150, "assessment", 60, "Charming, promising start"),
            _ev(90, "incident", 25, "Took credit for my work in front of leadership"),
            _ev(60, "incident", 25, "Shared confidential information with a competitor"),
            _ev(30, "incident", 10, "Made a promise then denied it later"),
            _ev(7, "assessment", 13, "Severe and repeated backstabs"),
        ]),
        _sample("Tomas Herrera", "Family", 9, 8, 7, "Low Risk", "Synergistic", "Fully Trust", [
            _ev(60, "assessment", 74, "Always been there"),
            _ev(30, "favor", 80, "Reliable during a family crisis"),
            _ev(10, "assessment", 80, "Trust fully reaffirmed"),
        ]),
    ]
# ---------------------------------------------------------------------------
# Terminal chart + display helpers
# ---------------------------------------------------------------------------
def _bar(value, width=24):
    value = max(0.0, min(100.0, value))
    filled = int(round(value / 100.0 * width))
    return "\u2588" * filled + "\u2591" * (width - filled)


def _fmt_date(ts):
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d")


def _fmt_date_short(ts):
    return datetime.fromtimestamp(ts).strftime("%m-%d")


def _resample_series(series, width):
    """Map a trust series to `width` evenly-spaced columns (step interpolation)."""
    if not series:
        return []
    min_ts = series[0][0]
    span = (series[-1][0] - min_ts) or 1.0
    values = []
    j = 0
    for c in range(width):
        t = min_ts + span * (c / (width - 1) if width > 1 else 0.0)
        while j + 1 < len(series) and series[j + 1][0] <= t:
            j += 1
        values.append(series[j][1])
    return values


def render_chart(profile, width=66, height=20):
    """Render the trust time series as an inline Unicode chart."""
    series = compute_trust_series(profile)
    values = _resample_series(series, width)
    step = 100.0 / height

    lines = []
    for r in range(height):
        y_hi = 100.0 - r * step
        y_lo = y_hi - step
        cells = []
        for v in values:
            hit = y_lo <= v < y_hi or (r == height - 1 and v <= y_lo + 1e-9)
            cells.append("\u2588" if hit else " ")
        label = f"{int(round(y_hi)):>3} \u2502" if r % 5 == 0 else "    \u2502"
        lines.append(label + "".join(cells))

    lines.append("  0 \u2514" + "\u2500" * width)

    # event markers row
    if series:
        min_ts = series[0][0]
        span = (series[-1][0] - min_ts) or 1.0
        mark = [" "] * width
        for ts, _trust, ev in series:
            if ev is None:
                continue
            col = int((ts - min_ts) / span * (width - 1))
            col = max(0, min(width - 1, col))
            mark[col] = EVENT_MARKERS.get(ev["kind"], "\u25cf")
        lines.append("    " + "".join(mark))

    # date axis
    if series:
        d0 = _fmt_date(series[0][0])
        d1 = _fmt_date(series[-1][0])
        gap = max(1, width - len(d0) - len(d1))
        lines.append("    " + d0 + " " * gap + d1)

    lines.append("")
    lines.append("  \u25cf assessment   \u25bc incident   \u25b2 favor")
    return "\n".join(lines)


def _velocity_note(vel):
    if vel > VELOCITY_CHANGE_THRESHOLD:
        return "improving"
    if vel < -VELOCITY_CHANGE_THRESHOLD:
        return "deteriorating"
    return "stable"


def _volatility_note(vol):
    if vol > 8.0:
        return "highly unstable"
    if vol > 3.0:
        return "some instability"
    return "stable"
# ---------------------------------------------------------------------------
# CLI application
# ---------------------------------------------------------------------------
class VaultCLI:
    def __init__(self, key, vault):
        self.key = key
        self.vault = vault

    def run(self):
        self._banner()
        while True:
            try:
                raw = input("\n> ").strip()
            except (EOFError, KeyboardInterrupt):
                console.print()
                break
            if not raw:
                continue
            op, _, arg = raw.partition(" ")
            op = op.lower()
            arg = arg.strip()
            if op in ("quit", "exit", "q"):
                break
            try:
                self._execute(op, arg)
            except (EOFError, KeyboardInterrupt):
                console.print("[dim]Cancelled.[/dim]")
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
        self._persist()
        console.print("[dim]Vault saved & encrypted. Goodbye.[/dim]")

    def _execute(self, op, arg):
        if op in ("help", "h", "?"):
            self._help()
        elif op in ("list", "ls"):
            self._list(arg)
        elif op in ("view", "show", "v"):
            self._view(arg)
        elif op in ("plot", "chart", "graph"):
            self._plot(arg)
        elif op in ("add", "new", "a"):
            self._add()
        elif op in ("edit", "e"):
            self._edit(arg)
        elif op in ("delete", "del", "rm", "d"):
            self._delete(arg)
        elif op in ("search", "find", "s"):
            self._list(arg)
        elif op in ("log", "note", "incident"):
            self._log(arg)
        elif op in ("favor", "good"):
            self._favor(arg)
        elif op in ("analyze", "summary"):
            self._analyze()
        elif op in ("export", "backup"):
            self._export()
        elif op in ("clear", "cls"):
            self._clear()
        else:
            console.print(f"[red]Unknown command '{op}'. Type 'help'.[/red]")

    # -- display ---------------------------------------------------------
    def _clear_screen(self):
        os.system("cls" if os.name == "nt" else "clear")

    def _banner(self):
        self._clear_screen()
        total = len(self.vault["profiles"])
        console.print(Panel(
            f"[bold]{APP_NAME}[/bold]\n"
            f"[dim]{total} profile(s). Trust is tracked as a time series. Type 'help'.[/dim]",
            border_style="cyan", box=box.ROUNDED))

    def _clear(self):
        self._banner()

    def _help(self):
        t = Table(title="Commands", box=box.ROUNDED, border_style="cyan")
        t.add_column("Command", style="bold cyan", no_wrap=True)
        t.add_column("Description")
        for cmd, desc in [
            ("list / ls [query]", "List profiles with their time-series trust score"),
            ("view / v <id|name>", "Full detail: chart, metrics, event timeline"),
            ("plot / chart <id|name>", "Show just the trust time-series chart"),
            ("add / a", "Add a new profile"),
            ("edit / e <id|name>", "Edit a profile (adds an assessment event)"),
            ("log / incident <id|name>", "Log an incident (negative event)"),
            ("favor / good <id|name>", "Log a favor (positive event)"),
            ("delete / d <id|name>", "Delete a profile"),
            ("analyze / summary", "Portfolio risk summary"),
            ("export / backup", "Export an encrypted backup file"),
            ("clear / cls", "Clear the screen"),
            ("help / ?", "Show this help"),
            ("quit / exit / q", "Save, encrypt and exit"),
        ]:
            t.add_row(cmd, desc)
        console.print(t)

    def _list(self, query=""):
        q = (query or "").lower()
        rows = []
        for i, p in enumerate(self.vault["profiles"], 1):
            if q and q not in (p.get("name", "") + " " + p.get("category", "")).lower():
                continue
            rows.append((i, p))
        if not rows:
            console.print("[yellow]No profiles match.[/yellow]")
            return
        t = Table(title="Profiles", box=box.ROUNDED, border_style="cyan")
        t.add_column("#", justify="right", style="dim")
        t.add_column("Name", style="bold")
        t.add_column("Category")
        t.add_column("Trust", justify="right")
        t.add_column("Trend", justify="center")
        t.add_column("Status")
        for i, p in rows:
            score = current_trust(p)
            band, color = score_band(score)
            vel = trust_velocity(p)
            trend = "\u2197" if vel > VELOCITY_CHANGE_THRESHOLD else ("\u2198" if vel < -VELOCITY_CHANGE_THRESHOLD else "\u2192")
            t.add_row(str(i), p.get("name") or "Unnamed", p.get("category", ""),
                      f"{score:.0f}%", trend, f"[{color}]{band}[/{color}]")
        console.print(t)

    def _find(self, arg):
        profiles = self.vault["profiles"]
        if not profiles:
            return None
        arg = (arg or "").strip()
        if arg == "":
            if len(profiles) == 1:
                return profiles[0]
            console.print("[yellow]Specify a profile by number or name.[/yellow]")
            return None
        try:
            idx = int(arg)
            if 1 <= idx <= len(profiles):
                return profiles[idx - 1]
        except ValueError:
            pass
        matches = [p for p in profiles if arg.lower() in (p.get("name") or "").lower()]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            console.print("[yellow]Multiple matches - be more specific.[/yellow]")
        else:
            console.print(f"[yellow]No profile matches '{arg}'.[/yellow]")
        return None

    def _plot(self, arg):
        p = self._find(arg)
        if p is None:
            return
        score = current_trust(p)
        band, color = score_band(score)
        console.print(f"[bold]{p.get('name') or 'Unnamed'}[/bold]  "
                      f"[{color}]trust {score:.0f}% ({band})[/{color}]")
        console.print(render_chart(p))

    def _view(self, arg):
        p = self._find(arg)
        if p is None:
            return
        score = current_trust(p)
        band, color = score_band(score)
        base = compute_raw_trust_score(p)
        vel = trust_velocity(p)
        vol = trust_volatility(p)
        change = total_change(p)
        impact = incident_impact(p)

        lines = []
        lines.append(f"[bold]{p.get('name') or 'Unnamed'}[/bold]  [dim]{p.get('category', '')}[/dim]")
        lines.append("")
        lines.append(f"[{color}]{_bar(score)}[/{color}]  [{color}]{score:.0f}%  {band}[/{color}]")
        lines.append(f"[dim]current assessment (ABI): {base:.0f}%   "
                     f"total change: {change:+.0f} pts[/dim]")
        lines.append("")
        lines.append(f"[bold]Benevolence[/bold] {p['benevolence']}/10   "
                     f"[bold]Integrity[/bold] {p['integrity']}/10   "
                     f"[bold]Ability[/bold] {p['ability']}/10")
        lines.append(f"[bold]Dark Triad[/bold]: {p['dark_triad_risk']}")
        lines.append(f"[bold]Reciprocity[/bold]: {p['reciprocity']}    "
                     f"[bold]Boundary[/bold]: {p['boundary_strategy']}")
        lines.append("")
        lines.append("[bold]Trust time series[/bold]")
        lines.append(render_chart(p))
        lines.append("")
        lines.append("[bold]Analysis[/bold]")
        lines.append(f"  Trend velocity:  {vel:+.2f} pts/day  ({_velocity_note(vel)})")
        lines.append(f"  Volatility:      {vol:.2f}  ({_volatility_note(vol)})")
        lines.append(f"  Total change:    {change:+.1f} pts")
        lines.append(f"  Incident load:   {impact:.2f}  (recency-weighted)")
        lines.append("")
        lines.append("[bold]Recent events[/bold]")
        events = sorted(p.get("events", []), key=lambda e: e["ts"], reverse=True)[:6]
        for e in events:
            marker = EVENT_MARKERS.get(e["kind"], "\u25cf")
            date = _fmt_date(e["ts"])
            note = e.get("note") or ""
            lines.append(f"  {marker} {date}  {note}  [dim](value {e['value']:.0f})[/dim]")
        lines.append("")
        lines.append(f"[italic dim]{recommendation(p, score)}[/italic dim]")
        console.print(Panel("\n".join(lines), border_style=color, box=box.ROUNDED))
    # -- mutations -------------------------------------------------------
    def _add(self):
        console.print(Panel("[bold]Add new profile[/bold]", border_style="cyan", box=box.ROUNDED))
        name = input("Name / alias: ").strip()
        if not name:
            console.print("[yellow]Aborted - a name is required.[/yellow]")
            return
        category = self._choose("Category", CATEGORIES)
        benevolence = self._int_input("Benevolence (goodwill without self-interest)", 1, 10, 5)
        integrity = self._int_input("Integrity (consistency & honesty)", 1, 10, 5)
        ability = self._int_input("Ability (competence & reliability)", 1, 10, 5)
        dark = self._choose("Dark Triad / backstab risk", DARK_TRIAD_LEVELS)
        reciprocity = self._choose("Reciprocity balance", RECIPROCITY_LEVELS)
        boundary = self._choose("Boundary strategy", BOUNDARY_STRATEGIES)
        p = new_profile(name)
        p["category"] = category
        p["benevolence"] = benevolence
        p["integrity"] = integrity
        p["ability"] = ability
        p["dark_triad_risk"] = dark
        p["reciprocity"] = reciprocity
        p["boundary_strategy"] = boundary
        append_event(p, "assessment", compute_raw_trust_score(p), "Initial assessment")
        self.vault["profiles"].append(p)
        self._persist()
        score = current_trust(p)
        band, color = score_band(score)
        console.print(f"[green]Added '{name}'.[/green]  [{color}]Trust {score:.0f}% ({band})[/{color}]")

    def _edit(self, arg):
        p = self._find(arg)
        if p is None:
            return
        console.print(Panel(f"[bold]Edit {p.get('name') or 'Unnamed'}[/bold] (blank keeps value)",
                            border_style="cyan", box=box.ROUNDED))
        v = input(f"Name [{p.get('name', '')}]: ").strip()
        if v:
            p["name"] = v
        p["category"] = self._choose("Category", CATEGORIES, p.get("category", "Friend"))
        p["benevolence"] = self._int_input("Benevolence", 1, 10, p["benevolence"])
        p["integrity"] = self._int_input("Integrity", 1, 10, p["integrity"])
        p["ability"] = self._int_input("Ability", 1, 10, p["ability"])
        p["dark_triad_risk"] = self._choose("Dark Triad", DARK_TRIAD_LEVELS, p["dark_triad_risk"])
        p["reciprocity"] = self._choose("Reciprocity", RECIPROCITY_LEVELS, p["reciprocity"])
        p["boundary_strategy"] = self._choose("Boundary", BOUNDARY_STRATEGIES, p["boundary_strategy"])
        append_event(p, "assessment", compute_raw_trust_score(p), "Reassessment")
        p["updated_at"] = time.time()
        self._persist()
        console.print("[green]Profile updated.[/green]")

    def _delete(self, arg):
        p = self._find(arg)
        if p is None:
            return
        name = p.get("name") or "Unnamed"
        confirm = input(f"Delete '{name}'? [y/N] ").strip().lower()
        if confirm not in ("y", "yes"):
            console.print("[dim]Cancelled.[/dim]")
            return
        self.vault["profiles"] = [x for x in self.vault["profiles"] if x["id"] != p["id"]]
        self._persist()
        console.print(f"[green]Deleted '{name}'.[/green]")

    def _log(self, arg):
        """Log an incident (negative event)."""
        p = self._find(arg)
        if p is None:
            return
        note = input("Incident description: ").strip()
        if not note:
            return
        sev = self._int_input("Severity (1 minor - 3 severe)", 1, 3, 2)
        append_event(p, "incident", INCIDENT_VALUES[sev], note)
        self._persist()
        score = current_trust(p)
        console.print(f"[green]Incident logged.[/green]  "
                      f"[yellow]trust now {score:.0f}%[/yellow]")

    def _favor(self, arg):
        """Log a favor (positive event)."""
        p = self._find(arg)
        if p is None:
            return
        note = input("Favor description: ").strip()
        if not note:
            return
        mag = self._int_input("Magnitude (1 small - 3 major)", 1, 3, 2)
        append_event(p, "favor", FAVOR_VALUES[mag], note)
        self._persist()
        score = current_trust(p)
        console.print(f"[green]Favor logged.[/green]  "
                      f"[cyan]trust now {score:.0f}%[/cyan]")

    def _analyze(self):
        profiles = self.vault["profiles"]
        if not profiles:
            console.print("[yellow]No profiles yet.[/yellow]")
            return
        counts = {"Safe": 0, "Caution": 0, "High Risk": 0}
        for p in profiles:
            band, _ = score_band(current_trust(p))
            counts[band] += 1
        lines = [f"[bold]Portfolio summary[/bold] - {len(profiles)} profile(s)", ""]
        for band, color in [("Safe", COLOR_SAFE), ("Caution", COLOR_CAUTION),
                            ("High Risk", COLOR_HIGH_RISK)]:
            n = counts[band]
            lines.append(f"  [{color}]{band:<11}[/{color}] [{color}]{_bar(n * 100.0 / len(profiles), 20)}[/{color}] {n}")
        lines.append("")
        lines.append("[bold]Highest risk (by time-series trust)[/bold]")
        for p in sorted(profiles, key=current_trust)[:3]:
            s = current_trust(p)
            band, color = score_band(s)
            lines.append(f"  [{color}]{s:>3.0f}%[/{color}]  {p.get('name') or 'Unnamed'}  [dim]({p.get('category', '')})[/dim]")
        lines.append("")
        lines.append("[bold]Fastest declining (30-day trend)[/bold]")
        for p in sorted(profiles, key=trust_velocity)[:3]:
            lines.append(f"  {trust_velocity(p):+.2f}/day  {p.get('name') or 'Unnamed'}")
        console.print(Panel("\n".join(lines), border_style="cyan", box=box.ROUNDED))

    def _export(self):
        self._persist()
        default = "vault_backup.enc"
        path = input(f"Export path [{default}]: ").strip() or default
        if not path.endswith(".enc"):
            path += ".enc"
        f = Fernet(self.key)
        ciphertext = f.encrypt(json.dumps(self.vault, indent=2).encode("utf-8"))
        with open(path, "wb") as fh:
            fh.write(ciphertext)
        console.print(f"[green]Encrypted backup written to {path}[/green]")

    # -- state / persistence --------------------------------------------
    def _persist(self):
        encrypt_vault(self.vault, self.key)

    # -- input helpers ---------------------------------------------------
    def _int_input(self, prompt, lo, hi, default):
        while True:
            s = input(f"{prompt} [{lo}-{hi}] (default {default}): ").strip()
            if not s:
                return default
            try:
                v = int(s)
            except ValueError:
                console.print("[red]Enter a whole number.[/red]")
                continue
            if lo <= v <= hi:
                return v
            console.print(f"[red]Must be between {lo} and {hi}.[/red]")

    def _choose(self, prompt, options, default=None):
        console.print(f"{prompt}:")
        for i, opt in enumerate(options, 1):
            mark = "  (current)" if opt == default else ""
            console.print(f"  {i}. {opt}{mark}")
        def_idx = options.index(default) + 1 if default in options else 1
        s = input(f"Choose [1-{len(options)}] (default {def_idx}): ").strip()
        if not s:
            return options[def_idx - 1]
        try:
            idx = int(s) - 1
            if 0 <= idx < len(options):
                return options[idx]
        except ValueError:
            pass
        console.print("[yellow]Invalid choice - keeping default.[/yellow]")
        return options[def_idx - 1]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    salt = load_or_create_salt()

    if os.path.exists(VAULT_FILE):
        try:
            pw = getpass.getpass("Master password: ")
        except (EOFError, KeyboardInterrupt):
            console.print()
            sys.exit(0)
        if not pw:
            console.print("[red]No password entered.[/red]")
            sys.exit(1)
        key = derive_key(pw, salt)
        try:
            vault = decrypt_vault(key)
        except InvalidToken:
            console.print("[red]Wrong password. Exiting.[/red]")
            sys.exit(1)
        except Exception as e:
            console.print(f"[red]Failed to open vault: {e}[/red]")
            sys.exit(1)
    else:
        console.print("[cyan]No vault found - creating a new one with sample data.[/cyan]")
        pw = getpass.getpass("New master password (min 8 chars): ")
        if len(pw) < 8:
            console.print("[red]Password must be at least 8 characters.[/red]")
            sys.exit(1)
        confirm = getpass.getpass("Confirm password: ")
        if pw != confirm:
            console.print("[red]Passwords do not match.[/red]")
            sys.exit(1)
        key = derive_key(pw, salt)
        vault = {"version": 1, "created_at": time.time(), "profiles": sample_profiles()}
        encrypt_vault(vault, key)
        console.print("[green]Vault created.[/green]")

    VaultCLI(key, vault).run()


if __name__ == "__main__":
    main()
