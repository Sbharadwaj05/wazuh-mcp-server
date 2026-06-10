#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# setup.sh — One-command setup for Wazuh + MCP Server testing environment
# ---------------------------------------------------------------------------
# Usage:
#   chmod +x scripts/setup.sh
#   ./scripts/setup.sh
#
# This script:
#   1. Creates the Wazuh manager config directory
#   2. Writes a minimal ossec.conf for the manager
#   3. Generates self-signed certs for the dashboard
#   4. Starts the Docker stack
#   5. Installs Python dependencies for the MCP server
# ---------------------------------------------------------------------------

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_DIR="$PROJECT_DIR/config/wazuh_manager"
CERTS_DIR="$PROJECT_DIR/config/certs"

echo "============================================"
echo " Wazuh MCP Server — Dev Environment Setup"
echo "============================================"
echo ""

# ------------------------------------------------------------------
# 1. Configuration directories
# ------------------------------------------------------------------
echo "[1/5] Creating configuration directories..."
mkdir -p "$CONFIG_DIR"
mkdir -p "$CERTS_DIR"

# ------------------------------------------------------------------
# 2. Minimal ossec.conf
# ------------------------------------------------------------------
echo "[2/5] Writing Wazuh manager ossec.conf..."
cat > "$CONFIG_DIR/ossec.conf" << 'OSSEOCONF'
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
  </alerts>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>

  <auth>
    <disabled>no</disabled>
    <port>1515</port>
    <use_source_ip>no</use_source_ip>
    <force_insert>yes</force_insert>
    <force_time>1</force_time>
    <purge>yes</purge>
    <use_password>no</use_password>
    <ssl_agent_ca>/var/ossec/etc/rootCA.pem</ssl_agent_ca>
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_manager_cert>/var/ossec/etc/manager.pem</ssl_manager_cert>
    <ssl_manager_key>/var/ossec/etc/manager-key.pem</ssl_manager_key>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>

  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/bin,/sbin,/boot</directories>
  </syscheck>

  <vulnerability-detector>
    <enabled>no</enabled>
  </vulnerability-detector>

  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
    <skip_nfs>yes</skip_nfs>
  </sca>

  <active-response>
    <disabled>no</disabled>
  </active-response>

  <!-- Indexer integration -->
  <indexer>
    <enabled>yes</enabled>
    <hosts>
      <host>https://wazuh.indexer:9200</host>
    </hosts>
    <ssl>
      <certificate_authorities>
        <ca>/var/ossec/etc/rootCA.pem</ca>
      </certificate_authorities>
      <certificate>/var/ossec/etc/manager.pem</certificate>
      <key>/var/ossec/etc/manager-key.pem</key>
    </ssl>
  </indexer>
</ossec_config>
OSSEOCONF

# ------------------------------------------------------------------
# 3. Generate self-signed certs for dashboard
# ------------------------------------------------------------------
echo "[3/5] Generating self-signed certificates for dashboard..."
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout "$CERTS_DIR/dashboard-key.pem" \
  -out "$CERTS_DIR/dashboard.pem" \
  -subj "/C=US/ST=State/L=City/O=Wazuh/CN=localhost" \
  2>/dev/null || echo "   (openssl not found — skipping cert generation)"

# ------------------------------------------------------------------
# 4. Start Docker stack
# ------------------------------------------------------------------
echo "[4/5] Starting Wazuh Docker stack..."
cd "$PROJECT_DIR"
docker compose up -d

echo ""
echo "Waiting for Wazuh manager API to become available..."
for i in $(seq 1 60); do
  if curl -k -s -o /dev/null -w "%{http_code}" https://localhost:55000/ 2>/dev/null | grep -q "200\|401"; then
    echo "   ✓ Wazuh API is responding!"
    break
  fi
  echo "   ... waiting (${i}s)"
  sleep 2
done

# ------------------------------------------------------------------
# 5. Install Python dependencies
# ------------------------------------------------------------------
echo "[5/5] Installing Python dependencies..."
pip install -e ".[dev]" 2>/dev/null || pip install mcp httpx python-dotenv

echo ""
echo "============================================"
echo " Setup complete!"
echo "============================================"
echo ""
echo " Wazuh Dashboard: https://localhost:443"
echo "   Username: admin"
echo "   Password: SecretPassword"
echo ""
echo " Wazuh API:      https://localhost:55000"
echo "   Username: admin"
echo "   Password: SecretPassword"
echo ""
echo " To start the MCP server:"
echo "   cd $PROJECT_DIR"
echo "   cp .env.example .env"
echo "   python -m wazuh_mcp.server"
echo ""
echo " Or configure Claude Desktop with:"
echo "   claude_desktop_config.json.example"
echo ""
