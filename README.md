# React2Shell Docker Scanner (CVE-2025-55182)

Bash script to **detect Docker containers running Next.js/React apps** that ship vulnerable versions of **React Server Components** libraries related to the _React2Shell_ vulnerability (CVE-2025-55182).

Targeted libraries:

- `react-server-dom-webpack`
- `react-server-dom-parcel`
- `react-server-dom-turbopack`

Versions treated as vulnerable in this script:

- `19.0.0`
- `19.1.0`
- `19.1.1`
- `19.2.0`

This script is designed for a **server hosting Coolify** with Next.js apps running inside Docker containers.

---

## How It Works

1. Fetches the container list using `docker ps`.
2. Skips infrastructure containers (Coolify core, Traefik, Postgres, Redis, Sentinel, Realtime).
3. For each **app container**:
   - Determines one or more app directories (`WorkingDir`, `/app`, `/usr/src/app`, `/srv`, etc.).
   - Searches inside those directories for files containing the RSC package names.
   - In those files, looks for vulnerable versions (`19.0.0`, `19.1.0`, `19.1.1`, `19.2.0`).
4. For each container, shows:
   - If it is **potentially vulnerable** (packages + versions found),
   - Or **no vulnerable RSC package detected**.
5. At the end, prints a summary: number of containers scanned and number flagged as vulnerable.

---

## Requirements

- Bash (Linux shell).
- Access to the **Docker host** (e.g. Hetzner VPS where Coolify runs).
- Docker installed and accessible:
  - `docker ps` must work.
- Sufficient privileges (usually `root` or `sudo`).

---

## Installation

On the Docker host (Coolify server):

```bash
sudo mkdir -p /opt/security
cd /opt/security

# Create the script
sudo nano react2shell-docker-scan.sh
# → paste the script content, then save

sudo chmod +x react2shell-docker-scan.sh
```

## Usage
Run a full scan from the Docker host:
```bash
cd /opt/security
sudo ./react2shell-docker-scan.sh
```

## Example output
```bash
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🔍 React2Shell Docker Scanner v2 (CVE-2025-55182)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📋 Detected containers:
  • 25d6aff78fc8 vckwc4w04g0088ss4w4csssk-2149... vckwc4w04g0088ss4w4csssk:...
  • cb78f1ede2ba k48owgkggc40w8g0woo0ckw4-2122... k48owgkggc40w8g0woo0ckw4:...
  • ...

━━━ 🔎 Scanning application containers ━━━

📦 Container: vckwc4w04g0088ss4w4csssk-2149...
    ID    : 25d6aff78fc8
    Image : vckwc4w04g0088ss4w4csssk:...
    Roots scanned : /app/ /app /srv
    🚨 Potentially vulnerable:
      • react-server-dom-webpack @ 19.0.0 found in: /app/pnpm-lock.yaml
      • react-server-dom-turbopack @ 19.2.0 found in: /app/package-lock.json
      • ...

📦 Container: k48owgkggc40w8g0woo0ckw4-2122...
    ID    : cb78f1ede2ba
    Image : k48owgkggc40w8g0woo0ckw4:...
    Roots scanned : /app/ /app /srv
    ✅ No vulnerable RSC package detected (heuristic text scan).

↷ Skipping infra container: coolify-proxy (traefik:v3.6)
↷ Skipping infra container: coolify-db (postgres:15-alpine)
```

## Interpreting the Results

### Container flagged as “Potentially vulnerable”

This means the script found:

- A **React Server Component package name**, and  
- One of the **vulnerable versions**:

  - `19.0.0`
  - `19.1.0`
  - `19.1.1`
  - `19.2.0`

in files under the scanned roots (lockfiles, build artifacts, etc.).

This is **heuristic**, not a full dependency resolver.  
It is a strong indicator you should check and patch that app, but **not** a formal SBOM analysis.

---

### Container marked “No vulnerable RSC package detected”

No matching vulnerable versions were found in the scanned paths.

This is a **good sign**, but you should still:

- Keep dependencies **up to date**
- Run regular security scans (e.g. **Trivy**, **Snyk**, etc.)

---

## What To Do If a Container Is Marked Vulnerable

1. **Identify the app in Coolify**

   - Match the container name (e.g. `vckwc4w04g0088ss4w4csssk-...`) with the deployed application in the **Coolify UI**.

2. **Update the app dependencies** in the corresponding repository, for example:

   ```bash
   # Using npm
   npm install react-server-dom-turbopack@latest react-server-dom-webpack@latest
   npm install next@latest react@latest react-dom@latest

   
3. **Clean and rebuild locally**
```bash
rm -rf node_modules .next
# optionally also remove old lockfiles if you want a clean resolution:
# rm -f package-lock.json pnpm-lock.yaml

npm install
npm run build
```
4. **Redeploy via Coolify**
- Redeploy the app so the new Docker image uses the patched versions.
5. **Re-run the scanner on the server**
  ```bash
  sudo /opt/security/react2shell-docker-scan.sh
```
Confirm the container is no longer flagged.
