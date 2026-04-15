<div align="center">

# ⚡ Z1Y4D XSS Lab

**23 progressively harder cross-site scripting challenges — built for the curious, the methodical, and the relentless.**

[![Node.js](https://img.shields.io/badge/Node.js-18%2B-brightgreen?style=flat-square&logo=node.js)](https://nodejs.org)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![Challenges](https://img.shields.io/badge/Challenges-23-orange?style=flat-square)]()
[![Zero Dependencies](https://img.shields.io/badge/External%20Deps-Zero-red?style=flat-square)]()

> A self-hosted, offline XSS training environment designed to take you from reflective basics to prototype pollution and DOM clobbering — no cloud accounts, no paywalls, no CTF gatekeeping.

</div>

---

## What Is This?

Most XSS tutorials stop at `<script>alert(1)</script>`. This lab doesn't.

XSS Lab is a hands-on training environment with **23 deliberately vulnerable web pages**, each implementing a specific (and intentionally flawed) defense. Your goal is to bypass it. Every level is isolated, self-explanatory, and backed by a writeup that explains the root cause, the correct fix, and where this class of bug shows up in the real world.

Built for:
- 🛡️ **Security engineers** building threat modeling or secure code review skills
- 🕵️ **Pentesters** sharpening their web application testing methodology
- 👩‍💻 **Developers** who want to understand injection flaws at the source level
- 🎓 **Students** looking for structured, progressive security training

---

## Quickstart

```bash
git clone https://github.com/ArtSecTest/artsec-xss-labs.git
cd artsec-xss-labs
npm install
npm start
```

Open **http://localhost:3000** in your browser (Chrome recommended).

---

## Challenge Index

| # | Name | Difficulty |
|---|------|------------|
| 01 | Hello, Reflected XSS | 🟢 Easy |
| 02 | Stored XSS Guestbook | 🟢 Easy |
| 03 | Script Tag Blocked | 🟡 Medium |
| 04 | Attribute Injection | 🟡 Medium |
| 05 | JavaScript Context | 🟡 Medium |
| 06 | Event Handler Blocklist | 🔴 Hard |
| 07 | Case & Keyword Filter | 🔴 Hard |
| 08 | DOM-Based XSS | 🔴 Hard |
| 09 | href Injection with Filters | ⚫ Expert |
| 10 | CSP Bypass | ⚫ Expert |
| 11 | Double Encoding Bypass | ⚫ Expert |
| 12 | Client-Side Template Injection | ⚫ Expert |
| 13 | postMessage XSS | ⚫ Expert |
| 14 | SVG Upload XSS | ⚫ Expert |
| 15 | Mutation XSS | ⚫ Expert |
| 16 | Recursive Keyword Filter | ⚫ Expert |
| 17 | The Polyglot | ⚫ Expert |
| 18 | DOM Clobbering | ⚫ Expert |
| 19 | Prototype Pollution to XSS | ⚫ Expert |
| 20 | Base Tag Injection | ⚫ Expert |
| 21 | Dangling Markup Injection | ⚫ Expert |
| 22 | JSON Injection in Script Block | ⚫ Expert |
| 23 | URL Scheme Bypass | ⚫ Expert |

**Levels 1–8** cover the foundational injection contexts: reflected, stored, DOM-based, attribute, and JavaScript sinks.  
**Levels 9–17** introduce intermediate techniques: CSP bypasses, encoding tricks, template injection, and mutation XSS.  
**Levels 18–23** go deep: DOM clobbering, prototype pollution chains, dangling markup, and encoding mismatches that break parsers.

---

## Features

### 📊 Progress Dashboard
Track your status across all 23 challenges from a central dashboard. Solved levels are marked clearly; unsolved ones stay neutral — no spoilers.

### 💡 Layered Hints
Every level ships with encoded hints (base64) so you can get unstuck without accidentally reading the answer in the page source. Peek only when you need to.

### 📖 Post-Solve Writeups
Writeups unlock automatically after you solve each challenge. They cover:
- **Why the payload worked** — the exact parser or browser behavior being exploited
- **The key lesson** — what the developer got wrong
- **Real-world impact** — where this pattern appears in production applications

### 📋 Technique Cheat Sheet
A reference page consolidating all injection contexts, filter bypass techniques, and correct defenses in one place. Your solutions are saved locally to `solutions.json` so the cheat sheet reflects your actual progress across restarts.

### 🔄 Full Reset
One button on the dashboard wipes your progress and lets you start over — useful for training runs or testing clean-state behavior.

---

## How It Works

Each level is a deliberately broken web page. The server applies a specific, flawed input filter or output encoding strategy. Your job is to craft a payload that triggers `alert()` — or in Level 21, exfiltrates data.

The challenges are not trick questions. Every bypass is rooted in real browser behavior, real parser quirks, and real bugs that have appeared in production software. If a payload works, it works for a reason — and the writeup will explain it.

No databases. No build step. No external services. The entire lab runs off a single Express server.

---

## Requirements

- **Node.js** 18 or higher
- A modern browser — Chrome is strongly recommended due to its predictable parser behavior

---

## Architecture Note

The lab is intentionally zero-dependency beyond Express. This makes it easy to audit, fork, and adapt. The entire challenge logic lives server-side in a single file, and every level's vulnerable endpoint is clearly labeled and commented. It's a useful reference for understanding what *not* to do when handling user input.

---

## ⚠️ Disclaimer

This project is for **educational purposes only**.

All vulnerabilities are intentional and exist solely to demonstrate how XSS works and why certain defenses fail. This lab is designed to run **locally** on your own machine.

**Do not** use any technique demonstrated here against systems you do not own or have explicit written authorization to test. Unauthorized access is illegal and unethical.

---

## Contributing

Found a bug, have an idea for a new challenge, or want to add a Docker Compose config? PRs and issues are welcome. Keep the zero-external-dependency philosophy intact.

---

<div align="center">

**Built by [ArtSec](https://github.com/ArtSecTest) · Hack responsibly.**

</div>
