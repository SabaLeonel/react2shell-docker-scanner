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
