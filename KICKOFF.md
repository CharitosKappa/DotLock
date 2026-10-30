# How to start DotLock in Claude Code

1. Unzip this kit into an empty folder (or a new GitHub repo) named `dotlock` and run `git init` if needed.
2. Open the folder in Claude Code (desktop app, claude.ai/code, or `claude` in a terminal inside the folder).
   Claude Code reads `CLAUDE.md` automatically; Codex reads `AGENTS.md` (same content).
3. Paste this as the first message:

```text
Read CLAUDE.md and everything under docs/. Then start task T1 from docs/TASKS.md.
Before writing code, tell me in 5 bullets what you will create for T1 and which tools must be
installed locally (Rust, Flutter, Xcode, Android SDK, Visual Studio). Then do it, run all checks,
tick T1 and commit.
```

4. For every next task:

```text
Do the next unchecked task in docs/TASKS.md. Follow the workflow in CLAUDE.md. Stop and ask me if
the spec is unclear (log it in docs/SPEC_QUESTIONS.md).
```

Tips

- Do M1–M2 (pure Rust) on any machine. iOS/macOS builds need a Mac; Windows builds need Windows or CI.
- Review every PR touching `core/dotlock-crypto` or `docs/SPEC.md` yourself before merging.
- Settle the open decisions in `docs/PLAN.md` before starting M3.
