#!/bin/sh
# Generate Config.toml from environment variables and start CompactLog.
cat > /app/Config.toml <<EOF
[server]
bind_addr = "0.0.0.0:${PORT:-8080}"
base_url = "${BASE_URL:-http://localhost:8080/}"

[storage]
provider = "local"

[storage.local]
path = "${STORAGE_PATH:-/data/storage}"

[keys]
private_key_path = "/app/certs/${LOG_KEY_NAME:-log}.key"
public_key_path = "/app/certs/${LOG_KEY_NAME:-log}.pub"

[validation]
enabled = false
EOF

exec compactlog
