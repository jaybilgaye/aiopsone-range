# Security policy

## This repository is vulnerable on purpose

Do not report the planted vulnerabilities. SQL injection, XSS, the hardcoded
example credentials, the public S3 bucket, the wide-open security group, the
root-user container — all deliberate, all documented in the README, all the
subject of a lesson.

## What is worth reporting

Open a private security advisory if you find:

- A **real** credential committed by accident — an actual access key, token or
  password belonging to anybody. The planted values are AWS's published example
  strings and are inert; anything else is a genuine mistake.
- Something that makes the lab unsafe **when run as documented** — locally, in a
  throwaway account. For example: a `terraform` default that could target an
  account the user did not intend, or a container that reaches outside its host.
- Anything that could cause harm to a third party rather than to the person
  deliberately running the exercise.

Use GitHub's private advisory flow rather than a public issue, and give it a
day or two before disclosing.

## What this lab will never contain

- Real credentials, real account IDs, or anything that resolves to a live resource.
- Working exploit payloads beyond what a lesson needs to make its point. The aim
  is to show a class of flaw and how to detect and fix it, not to ship tooling.
- Anything that phones home, or that is useful for attacking somebody else.
