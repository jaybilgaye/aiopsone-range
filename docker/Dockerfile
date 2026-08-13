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

# FLAW 1 — unpinned, outdated base. `latest` is not a version, and this major
# is long past its support window, so the OS package CVE count is high.
FROM node:16

# FLAW 2 — a secret baked into a layer. Even if a later layer deletes it, it
# stays in the image history and `docker history` will show it. These are AWS's
# published example values and are inert.
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
ENV DB_PASSWORD=hunter2

WORKDIR /app

# FLAW 3 — copying everything, including .git, .env and node_modules if present.
# There is no .dockerignore in this repo, also on purpose.
COPY . .

# FLAW 4 — installing with no lockfile guarantee, and pulling extra tooling into
# the runtime image that has no business being in production.
RUN npm install --unsafe-perm \
    && apt-get update \
    && apt-get install -y curl netcat-openbsd \
    && echo "done"

# FLAW 5 — no USER directive, so this runs as root. Dockle flags this as CIS-DI-0001
# and it is the single most common finding on a first image scan.

# FLAW 6 — no HEALTHCHECK, so an orchestrator cannot tell a wedged container from
# a working one.

EXPOSE 3000

CMD ["node", "app/server.js"]
