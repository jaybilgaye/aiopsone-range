# ⚠️  INTENTIONALLY VULNERABLE IMAGE — teaching material for aiopsone.com
#
# Target of the container chapter: Hadolint (Dockerfile lint), Dockle (CIS image
# checks), Trivy and Grype (CVE scanning), Docker Scout.
#
# Every line below breaks a rule those tools check. Build it, scan it, then fix
# it — the corrected Dockerfile is in the lesson, not here.
#
#   docker build -f docker/Dockerfile -t range-app:vulnerable .
#   hadolint docker/Dockerfile
#   trivy image range-app:vulnerable
#
# Do not push this image to a public registry.

# FLAW 1 — outdated base. Node 18 reached end-of-life in April 2025, and the
# tag floats rather than pinning a digest, so the OS package CVE count is high.
FROM node:26

# FLAW 2 — a secret baked into a layer. Even if a later layer deletes it, it
# stays in the image history and `docker history` will show it. Fabricated
# values, inert — deliberately not AWS's published example key, which scanners
# allowlist.
ENV AWS_ACCESS_KEY_ID=AKIA3XZP7QK2WVNR8TLM
ENV AWS_SECRET_ACCESS_KEY=kR8fT2wPmZ4vN7bXcQ1yJ6hL0sD3gA5eU9iO2pWn
ENV DB_PASSWORD=hunter2

WORKDIR /app

# FLAW 3 — copying everything, including .git, .env and node_modules if present.
# There is no .dockerignore in this repo, also on purpose.
COPY . .

# FLAW 4 — installing with no lockfile guarantee, and pulling extra tooling into
# the runtime image that has no business being in production.
RUN cd /app/app && npm install --unsafe-perm \
    && apt-get update \
    && apt-get install -y curl netcat-openbsd \
    && echo "done"

# FLAW 5 — no USER directive, so this runs as root. Dockle flags this as CIS-DI-0001
# and it is the single most common finding on a first image scan.

# FLAW 6 — no HEALTHCHECK, so an orchestrator cannot tell a wedged container from
# a working one.

# The container is its own network namespace, so bind all interfaces inside it.
# Publish to the host's loopback only:  docker run -p 127.0.0.1:3100:3000
ENV HOST=0.0.0.0

EXPOSE 3000

CMD ["node", "app/server.js"]
