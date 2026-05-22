<div align="center">

# 🔐 envvault

**Encrypt your `.env` files and sync them across machines via private GitHub Gist.**

[![Go Version](https://img.shields.io/badge/Go-1.21+-00acd7?style=for-the-badge&logo=go&logoColor=white)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![AES-256-GCM](https://img.shields.io/badge/Encryption-AES--256--GCM-blueviolet?style=for-the-badge)]()
[![GitHub Gist](https://img.shields.io/badge/Sync-GitHub%20Gist-181717?style=for-the-badge&logo=github)](https://gist.github.com)
[![Zero Dependencies](https://img.shields.io/badge/Server-None-orange?style=for-the-badge)]()

</div>

---

## 💡 What is this?

**envvault** is a tiny CLI that encrypts your `.env` files with a master password and stores the ciphertext in a **private GitHub Gist**. Pull it on any machine with the same password. No server, no cloud service, no BS.

```
Machine A                          GitHub Gist (private)
─────────────────                  ──────────────────────
.env  ──encrypt──▶  ciphertext  ──▶  env.enc (base64 blob)
                                           │
Machine B                                  │
─────────────────                          ▼
.env  ◀──decrypt──  ciphertext  ◀──  env.enc (base64 blob)
```

- 🔒 **AES-256-GCM** encryption with **PBKDF2** key derivation (100k iterations)
- 🔑 **Single master password** — same password on every machine
- 🙈 **Private Gist** — encrypted blob only, never plaintext
- 📦 **Multi-project** — each project gets its own Gist, tracked locally
- ⚡ **Zero config** after first setup

---

## 🚀 Install

```bash
git clone https://github.com/BaxQC/envvault
cd envvault
go build -o envvault .

# Move to PATH (Linux/Mac)
mv envvault /usr/local/bin/

# Or on Windows — move envvault.exe somewhere in your PATH
```

---

## ⚙️ Setup

### 1. Create a GitHub Personal Access Token

1. Go to [github.com/settings/tokens](https://github.com/settings/tokens)
2. **Generate new token (classic)**
3. Scopes: check **`gist`** only
4. Copy the token

### 2. Save it

```bash
envvault login ghp_xxxxxxxxxxxxxxxxxxxx
```

Token is stored in `~/.envvault/config.json` with `0600` permissions.

---

## 📖 Usage

### Push (encrypt + upload)

```bash
# Uses current directory name as project, encrypts .env
envvault push

# Custom project name and file
envvault push myapp .env.production
```

You'll be prompted for a master password (and confirmation on first push).

### Pull (download + decrypt)

```bash
# On another machine — pulls and writes .env
envvault pull

# Custom project and output file
envvault pull myapp .env.production
```

### List projects

```bash
envvault list
```

```
📦 Stored projects:
  myapp                → gist:abc123def456
  backend-api          → gist:xyz789ghi012
```

### Delete a project

```bash
envvault delete myapp
# Removes from local config only — Gist stays on GitHub
```

---

## 🔐 Security

| Property | Detail |
|---|---|
| Algorithm | AES-256-GCM (authenticated encryption) |
| Key derivation | PBKDF2-SHA256, 100,000 iterations |
| Salt | 32 bytes, random per push |
| Nonce | Random per push |
| Storage | Private GitHub Gist (encrypted blob only) |
| Local config | `~/.envvault/config.json` — mode `0600` |
| Written `.env` | Mode `0600` |

Your plaintext **never leaves your machine**. Only the encrypted base64 blob is uploaded.

> ⚠️ If you forget your master password, the data cannot be recovered — there is no reset.

---

## 🗺️ Roadmap

- [ ] `envvault rotate` — re-encrypt with a new password
- [ ] `envvault diff` — show what changed before pulling
- [ ] Team support — share a Gist ID with a teammate
- [ ] Shell completion (bash/zsh/fish)

---

## 📄 License

MIT © [Bax](https://github.com/BaxQC)
