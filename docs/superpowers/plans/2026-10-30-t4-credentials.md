# T4 requirements review

Read AGENTS.md, PLAN, SPEC §§3,4, TASKS, TESTING and THREAT_MODEL.
T3 was merged as PR #3 after successful CI on all runners, including the
dedicated 2 GiB Linux test (run 41097450189).

Status: stopped at the spec review gate required by AGENTS.md golden rule 1.
No T4 credential or phrase behavior has been implemented.
See SPEC_QUESTIONS Q1/Q2 for the missing custom recovery phrase policy.

Proposed scope, awaiting approval: defer custom recovery phrases from v1, retain
pattern/passphrase credentials and generated/validated 12-word English BIP-39.
If approved, change SPEC/TASKS explicitly before implementation. If custom
phrases are retained, settle Q1 and Q2 in a spec PR first.

Implementation outline after the spec decision:

1. Write table-driven pattern tests: bounds, repeats, six-dot minimum, direction
   changes, lattice points auto-added in order, and byte encoding prefixes.
2. Test NFKD passphrase encoding, normalized character count, eight-character
   minimum and preserved whitespace. All owned secret buffers must zeroize.
3. Test BIP-39 generation/parsing, 12-word/128-bit restriction, English words,
   invalid words/checksums and phrase round trips. No Debug/Display on secrets.
4. Add advisory pattern-strength tests against §3's length/turn guidance; keep
   strength reporting separate from format validity and recovery acceptance.
5. Implement the agreed scope only in dotlock-crypto, run required Rust/Flutter
   checks, source review, changelog and draft PR; tick T4 only after merge.
