# DotLock Threat Model (v1)

## Assets

User photos, videos, files, their names and metadata; the number of vaults; credentials and recovery phrases.

## Adversaries and what DotLock promises

| Adversary | Capability | DotLock's protection |
| --- | --- | --- |
| Casual snooper | Has the unlocked phone for a few minutes | Vault needs its own pattern; wrong pattern shows an empty vault; app-switcher blur; optional disguise icon |
| Thief / forensic examiner | Copies the app container from a locked or unlocked device | All content and metadata are AEAD ciphertext; vault count hidden by 16 fixed slots; offline guessing costs one Argon2id run per guess |
| Coercer | Forces the user to open the app | Duress pattern opens a decoy vault and silently wipes other local slots |
| Cloud provider / our own server / subpoena | Reads everything on the server | Server holds ciphertext, token hashes, sizes and timestamps only; no accounts, no keys |
| Network attacker | Observes or modifies traffic | TLS + AEAD; HMAC request auth; tampering fails closed |
| Share-phrase interceptor | Obtains an unused share phrase | Can claim once; owner can revoke; expiry enforced server-side |

## Explicit non-goals (say so honestly in UI and website)

- A compromised or jailbroken/rooted device while a vault is open: keys and plaintext are in app memory.
- A weak pattern: a 6-dot pattern is roughly as guessable as a 4-digit PIN offline. We show a strength
  meter and recommend 8+ dots with several turns, or a passphrase.
- Losing both the credential and the recovery phrase: data is unrecoverable by design.
- Content the user exported or that a share recipient copied outside DotLock.
- Physical-camera photos of the screen.
- Duress against a forensic examiner who imaged the device beforehand, or who inspects the cloud bucket.
- Traffic analysis (backup timing and sizes are visible to the server and network).

## Residual metadata

- Header shows DotLock is installed and its Argon2 parameters.
- Object count and approximate (Padmé-rounded) sizes are visible in the container and in the cloud.
- Store purchase records exist with Apple/Google/Microsoft; they are not linked to buckets by DotLock.
