#!/bin/bash
# PentestAI v8 - Ubuntu Backend Setup
# Run: sudo bash setup.sh

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}==================================================${NC}"
echo -e "${YELLOW}   PentestAI v8 - Ubuntu Backend Installer        ${NC}"
echo -e "${YELLOW}==================================================${NC}"
echo ""

INSTALL_DIR="/opt/pentest-ai"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# 1. Prerequisite check
echo -e "${YELLOW}[1/7] Checking prerequisites...${NC}"

errors=0

if ! command -v python3 &>/dev/null; then
    echo -e "  ${RED}x python3 not found -> sudo apt install -y python3 python3-pip${NC}"
    errors=1
else
    echo -e "  ${GREEN}OK python3 $(python3 --version 2>&1 | awk '{print $2}')${NC}"
fi

if ! command -v pip3 &>/dev/null; then
    echo -e "  ${RED}x pip3 not found -> sudo apt install -y python3-pip${NC}"
    errors=1
else
    echo -e "  ${GREEN}OK pip3${NC}"
fi

if ! command -v psql &>/dev/null; then
    echo -e "  ${RED}x PostgreSQL not found -> sudo apt install -y postgresql postgresql-contrib${NC}"
    errors=1
else
    echo -e "  ${GREEN}OK PostgreSQL $(psql --version 2>&1 | awk '{print $3}')${NC}"
fi

if ! systemctl is-active --quiet postgresql 2>/dev/null; then
    echo -e "  ${YELLOW}! PostgreSQL is not running, attempting to start it...${NC}"
    systemctl start postgresql 2>/dev/null || true
    sleep 1
    if ! systemctl is-active --quiet postgresql 2>/dev/null; then
        echo -e "  ${RED}x PostgreSQL failed to start${NC}"
        errors=1
    else
        echo -e "  ${GREEN}OK PostgreSQL started${NC}"
    fi
fi

if ! command -v redis-cli &>/dev/null; then
    echo -e "  ${YELLOW}! Redis not found - installing...${NC}"
    apt install -y redis-server 2>/dev/null || true
fi
if ! systemctl is-active --quiet redis-server 2>/dev/null && ! systemctl is-active --quiet redis 2>/dev/null; then
    systemctl start redis-server 2>/dev/null || systemctl start redis 2>/dev/null || true
fi
if redis-cli ping 2>/dev/null | grep -q PONG; then
    echo -e "  ${GREEN}OK Redis OK${NC}"
else
    echo -e "  ${YELLOW}! Redis unavailable - the system will run without it${NC}"
fi

if [ $errors -eq 1 ]; then
    echo ""
    echo -e "${RED}Install the missing prerequisites, then run this script again.${NC}"
    exit 1
fi

# 2. Creating directories
echo ""
echo -e "${YELLOW}[2/7] Creating directories...${NC}"

mkdir -p "$INSTALL_DIR/reports"
mkdir -p "$INSTALL_DIR/backend"
mkdir -p /var/log/pentestai
echo -e "  ${GREEN}OK $INSTALL_DIR created${NC}"

# 3. Copying files
echo ""
echo -e "${YELLOW}[3/7] Copying files...${NC}"

cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR/backend/" 2>/dev/null || true
cp "$SCRIPT_DIR"/.env* "$INSTALL_DIR/backend/" 2>/dev/null || true
echo -e "  ${GREEN}OK Files copied to $INSTALL_DIR/backend${NC}"

# 4. Installing Python dependencies
echo ""
echo -e "${YELLOW}[4/7] Installing Python dependencies...${NC}"

cd "$INSTALL_DIR/backend"

pip3 install --break-system-packages -r requirements.txt 2>/dev/null
RET=$?
if [ $RET -ne 0 ]; then
    echo -e "  ${YELLOW}-> Retrying without --break-system-packages...${NC}"
    pip3 install -r requirements.txt
    RET=$?
fi
if [ $RET -ne 0 ]; then
    echo -e "  ${RED}x pip install failed${NC}"
    exit 1
fi
echo -e "  ${GREEN}OK Dependencies installed${NC}"

# 5. Configuring .env
echo ""
echo -e "${YELLOW}[5/7] Configuring .env...${NC}"

cd "$INSTALL_DIR/backend"

if [ ! -f .env ]; then
    if [ -f .env.example ]; then
        cp .env.example .env
    else
        cat > .env << 'ENVEOF'
SECRET_KEY=pentestai-v8-default-change-me
FERNET_KEY=
DATABASE_URL=postgresql+asyncpg://ai:ai_password@localhost:5432/pentestai
REDIS_URL=redis://localhost:6379/0
KALI_AGENT_URL=http://192.168.57.10:9000
KALI_AGENT_TOKEN=pentestai-kali-secret-v8
DEBUG=false
ENVEOF
    fi

    # Generate SECRET_KEY
    SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null)
    if [ -n "$SECRET" ]; then
        sed -i "s|change-this-to-a-random-64-character-string|$SECRET|" .env 2>/dev/null || true
        sed -i "s|pentestai-v8-default-change-me|$SECRET|" .env 2>/dev/null || true
    fi

    # Generate FERNET_KEY
    FERNET=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null)
    if [ -n "$FERNET" ]; then
        sed -i "s|^FERNET_KEY=$|FERNET_KEY=$FERNET|" .env 2>/dev/null || true
    fi

    echo -e "  ${GREEN}OK .env generated${NC}"
else
    echo -e "  ${GREEN}OK .env already exists - keeping it${NC}"
fi

# 6. Configuring PostgreSQL
echo ""
echo -e "${YELLOW}[6/7] Configuring PostgreSQL...${NC}"

# User ai
su - postgres -c "psql -tc \"SELECT 1 FROM pg_roles WHERE rolname='ai'\"" 2>/dev/null | grep -q 1
if [ $? -ne 0 ]; then
    su - postgres -c "psql -c \"CREATE USER ai WITH PASSWORD 'ai_password';\"" 2>/dev/null
    echo -e "  ${GREEN}OK User 'ai' created${NC}"
else
    echo -e "  ${GREEN}OK User 'ai' already exists${NC}"
fi

# Database pentestai
su - postgres -c "psql -tc \"SELECT 1 FROM pg_database WHERE datname = 'pentestai'\"" 2>/dev/null | grep -q 1
if [ $? -ne 0 ]; then
    su - postgres -c "psql -c \"CREATE DATABASE pentestai OWNER ai;\"" 2>/dev/null
    echo -e "  ${GREEN}OK Database 'pentestai' created${NC}"
else
    echo -e "  ${GREEN}OK Database 'pentestai' already exists${NC}"
fi

# Permissions
su - postgres -c "psql -c \"GRANT ALL PRIVILEGES ON DATABASE pentestai TO ai;\"" 2>/dev/null || true
su - postgres -c "psql -d pentestai -c \"GRANT ALL ON SCHEMA public TO ai;\"" 2>/dev/null || true
su - postgres -c "psql -d pentestai -c \"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO ai;\"" 2>/dev/null || true
echo -e "  ${GREEN}OK PostgreSQL configured${NC}"

# 7. systemd service
echo ""
echo -e "${YELLOW}[7/7] Creating the systemd service...${NC}"

systemctl stop pentestai 2>/dev/null || true

cat > /etc/systemd/system/pentestai.service << EOF
[Unit]
Description=PentestAI v8 Backend
After=network.target postgresql.service redis-server.service

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}/backend
ExecStart=/usr/bin/python3 -m uvicorn api.main:app --host 0.0.0.0 --port 7000 --workers 1
Restart=on-failure
RestartSec=5
Environment=PYTHONPATH=${INSTALL_DIR}/backend

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable pentestai 2>/dev/null
systemctl restart pentestai

sleep 3

if systemctl is-active --quiet pentestai; then
    echo -e "  ${GREEN}OK pentestai service started!${NC}"
else
    echo -e "  ${RED}x The service did not start. Latest lines:${NC}"
    echo ""
    journalctl -u pentestai --no-pager -n 20
    echo ""
    echo -e "${YELLOW}  Debug: sudo journalctl -u pentestai -f${NC}"
    echo -e "${YELLOW}  Manual: cd $INSTALL_DIR/backend && python3 -m uvicorn api.main:app --host 0.0.0.0 --port 7000${NC}"
fi

# Summary
echo ""
echo -e "${GREEN}==================================================${NC}"
echo -e "${GREEN}  PentestAI v8 installation completed!${NC}"
echo ""
echo -e "${GREEN}  Web UI:     http://192.168.57.20:7000${NC}"
echo -e "${GREEN}  Login:      http://192.168.57.20:7000/login${NC}"
echo -e "  Admin:      ${YELLOW}myth${NC} / ${YELLOW}Myth04\$\$${NC}"
echo -e "  Pentester:  ${YELLOW}hacker${NC} / ${YELLOW}hacker\$\$${NC}"
echo ""
echo -e "${GREEN}  Commands:${NC}"
echo -e "    sudo systemctl status pentestai"
echo -e "    sudo journalctl -u pentestai -f"
echo -e "    sudo systemctl restart pentestai"
echo -e "${GREEN}==================================================${NC}"
