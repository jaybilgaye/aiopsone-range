# ⚠️ THE AiOpsOne RANGE — INTENTIONALLY VULNERABLE

> **This repository contains deliberately insecure code and infrastructure.**
> It exists to be scanned, attacked and fixed as a teaching exercise.
> **Do not deploy any part of it to a public endpoint. Do not run the Terraform
> in an AWS account you care about. Do not copy any of it into production.**

If you landed here from a search result and were looking for a secure example,
this is the opposite of that. Every file here is wrong on purpose.

---

## What this is

Three shared broken artifacts. Every lesson on [aiopsone.com](https://www.aiopsone.com)
scans, attacks or fixes one of them — so the whole curriculum measures against
the same target instead of a fresh contrived example each time.

| Artifact | What it is | Planted problems |
|---|---|---|
| `app/` | A small Node/Express app | SQL injection, reflected XSS, hardcoded credentials, known-vulnerable dependencies |
| `docker/` | A Dockerfile for that app | Runs as root, outdated base, unpinned tags, a secret baked into a layer |
| `terraform/` | The "broken AWS account" | Public S3 bucket, over-permissioned IAM, security group open to the world, no logging, unencrypted storage |

## Rules for running it

**The app**

- Run it **locally only** — `localhost`, or a container on your own machine.
- Never put it behind a public IP, a tunnel, ngrok, or a cloud load balancer.
  A running vulnerable app on a public address gets found by automated scanners
  in minutes, and then it is someone else's problem too.
- Spin it up, do the exercise, tear it down.

**The Terraform**

- Use a **throwaway AWS account** you are willing to delete. Not your main
  account, not your employer's, not one with anything else in it.
- **Set a billing alarm before your first `apply`.** This is the single most
  common way a lab costs someone real money.
- Run `terraform destroy` when you finish the exercise. There is a teardown
  section in every lesson that uses this.
- The Terraform deliberately has no default region or profile. You must pass
  them explicitly, so you cannot apply it to the wrong account by muscle memory.

**Credentials**

- There are no real credentials in this repository, and there never will be.
- The "secrets" planted for scanner exercises are AWS's own published example
  values (`AKIAIOSFODNN7EXAMPLE` and friends). They are inert.
- Never commit a real key to your fork. If you do: rotate it first, then worry
  about the git history. See the
  [pre-commit lesson](https://www.aiopsone.com/blog/gitleaks-precommit-secrets/).

## Quick start

```bash
git clone https://github.com/jaybilgaye/aiopsone-range
cd aiopsone-range

# App — local only
cd app && npm install && npm start        # http://localhost:3000

# Scanners — see the lessons for each
gitleaks git .
semgrep --config auto app/
trivy fs .
checkov -d terraform/
```

## Which lesson uses what

Each lesson on the site names the branch or directory it works against. Start
with [Secure the Pipeline](https://www.aiopsone.com/tracks/secure-the-pipeline)
and follow it in order — the artifacts are designed to be scanned shift-left,
in the same sequence a real pipeline would.

## Reporting

Vulnerabilities in this repository are **not bugs** — they are the content.
Please do not open issues for them.

If you find something genuinely unintended — a real credential committed by
accident, or something that makes the lab unsafe to run **locally** in the way
described above — see [SECURITY.md](SECURITY.md).

## Licence

MIT. Use it to learn. Do not use it to build anything real.
