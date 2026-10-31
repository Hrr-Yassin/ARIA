#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# PentestAI v10 overlay installer
#
# Usage:
#   ./apply_v10_overlay.sh /path/to/pentest-fixed
#
# This script:
#   1. Backs up the v9 files that v10 replaces (to ./backup_v9/)
#   2. Copies the v10 files on top of the existing project
#   3. Splices the v10 router additions into api/routers/pentest.py
#   4. Installs the new Python dependencies
# ═══════════════════════════════════════════════════════════════════════

set -e

OVERLAY_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -z "$1" ]; then
  echo "Usage: $0 /path/to/pentest-fixed"
  exit 1
fi

TARGET_DIR="$(cd "$1" && pwd)"

if [ ! -d "$TARGET_DIR" ]; then
  echo "ERROR: $1 is not a directory"
  exit 1
fi

if [ ! -f "$TARGET_DIR/api/routers/pentest.py" ]; then
  echo "ERROR: $TARGET_DIR doesn't look like a pentest-fixed project"
  echo "       (api/routers/pentest.py not found)"
  exit 1
fi

echo "╔══════════════════════════════════════════════════════╗"
echo "║  PentestAI v10 Overlay                                ║"
echo "║  Source:  $OVERLAY_DIR"
echo "║  Target:  $TARGET_DIR"
echo "╚══════════════════════════════════════════════════════╝"

# 1) Backup
BACKUP_DIR="$TARGET_DIR/backup_v9_$(date +%Y%m%d_%H%M%S)"
echo "→ Backing up v9 originals to $BACKUP_DIR"
mkdir -p "$BACKUP_DIR/agents" "$BACKUP_DIR/config" "$BACKUP_DIR/memory" \
         "$BACKUP_DIR/llm" "$BACKUP_DIR/api/routers" \
         "$BACKUP_DIR/web/static/scripts" "$BACKUP_DIR/web/static/styles"

cp -v "$TARGET_DIR/agents/orchestrator_agent.py"       "$BACKUP_DIR/agents/"       || true
cp -v "$TARGET_DIR/agents/attack_planner_agent.py"     "$BACKUP_DIR/agents/"       || true
cp -v "$TARGET_DIR/agents/base_agent.py"               "$BACKUP_DIR/agents/"       || true
cp -v "$TARGET_DIR/config/settings.py"                 "$BACKUP_DIR/config/"       || true
cp -v "$TARGET_DIR/config/tools_registry.py"           "$BACKUP_DIR/config/"       || true
cp -v "$TARGET_DIR/memory/attack_knowledge_base.py"    "$BACKUP_DIR/memory/"       || true
cp -v "$TARGET_DIR/memory/vector_store.py"             "$BACKUP_DIR/memory/"       || true
cp -v "$TARGET_DIR/memory/database_models.py"          "$BACKUP_DIR/memory/"       || true
cp -v "$TARGET_DIR/llm/pool_manager.py"                "$BACKUP_DIR/llm/"          || true
cp -v "$TARGET_DIR/api/routers/pentest.py"             "$BACKUP_DIR/api/routers/"  || true
cp -v "$TARGET_DIR/web/index.html"                     "$BACKUP_DIR/web/"          || true
cp -v "$TARGET_DIR/web/static/scripts/app.js"          "$BACKUP_DIR/web/static/scripts/" || true
cp -v "$TARGET_DIR/web/static/styles/index.css"        "$BACKUP_DIR/web/static/styles/"  || true
cp -v "$TARGET_DIR/requirements.txt"                   "$BACKUP_DIR/"              || true

# 2) Copy new & replacement files
echo "→ Copying v10 files"
cp -v "$OVERLAY_DIR/memory/parsers.py"                  "$TARGET_DIR/memory/"
cp -v "$OVERLAY_DIR/memory/playbook_store.py"           "$TARGET_DIR/memory/"
cp -v "$OVERLAY_DIR/memory/vector_store.py"             "$TARGET_DIR/memory/"
cp -v "$OVERLAY_DIR/memory/attack_knowledge_base.py"    "$TARGET_DIR/memory/"
cp -v "$OVERLAY_DIR/memory/database_models.py"          "$TARGET_DIR/memory/"
cp -v "$OVERLAY_DIR/config/cve_enricher.py"             "$TARGET_DIR/config/"
cp -v "$OVERLAY_DIR/config/settings.py"                 "$TARGET_DIR/config/"
cp -v "$OVERLAY_DIR/config/tools_registry.py"           "$TARGET_DIR/config/"
cp -v "$OVERLAY_DIR/llm/pool_manager.py"                "$TARGET_DIR/llm/"
cp -v "$OVERLAY_DIR/agents/base_agent.py"               "$TARGET_DIR/agents/"
cp -v "$OVERLAY_DIR/agents/autonomous_engine.py"        "$TARGET_DIR/agents/"
cp -v "$OVERLAY_DIR/agents/orchestrator_agent.py"       "$TARGET_DIR/agents/"
cp -v "$OVERLAY_DIR/agents/attack_planner_agent.py"     "$TARGET_DIR/agents/"
cp -v "$OVERLAY_DIR/web/index.html"                     "$TARGET_DIR/web/"
cp -v "$OVERLAY_DIR/web/static/scripts/app.js"          "$TARGET_DIR/web/static/scripts/"
cp -v "$OVERLAY_DIR/web/static/styles/index.css"        "$TARGET_DIR/web/static/styles/"
cp -v "$OVERLAY_DIR/requirements.txt"                   "$TARGET_DIR/"

# 3) Splice v10 router additions into pentest.py
PENTEST_ROUTER="$TARGET_DIR/api/routers/pentest.py"
V10_MARKER="# ══ V10 ROUTES ═════════════════════════════════════════════"

if grep -q "$V10_MARKER" "$PENTEST_ROUTER"; then
  echo "→ v10 routes already spliced into pentest.py — skipping"
else
  echo "→ Splicing v10 routes into $PENTEST_ROUTER"

  # Add v10 imports near the top (after existing imports)
  python3 - <<PY
import re
p = "$PENTEST_ROUTER"
with open(p, 'r') as f:
    src = f.read()

# Add v10 imports right after the last existing import
v10_imports = '''
# ── v10 imports ─────────────────────────────────────────────────────────
from agents.autonomous_engine import autonomous_engine
from memory.playbook_store import playbook_store
from memory.database_models import async_session, DecisionLog
from sqlalchemy import select, desc
'''

# Find a stable insertion point: just after the last "from ... import" line
# in the first 100 non-empty lines.
lines = src.splitlines()
last_import = 0
for i, line in enumerate(lines[:80]):
    if re.match(r'^(from|import)\s+\w', line):
        last_import = i
insertion = last_import + 1
lines.insert(insertion, v10_imports)
src = "\\n".join(lines)

# Append the v10 routes block
v10_routes_file = "$OVERLAY_DIR/api/routers/pentest_v10_additions.py"
with open(v10_routes_file, 'r') as f:
    additions = f.read()

# Strip the header docstring + comment-block — keep only the code
# (everything from the first class/def/@router onward)
m = re.search(r'^# ── Pydantic models', additions, re.MULTILINE)
if m:
    additions = additions[m.start():]

marker = "$V10_MARKER"
block = f"\\n\\n{marker}\\n{additions}\\n"
src = src.rstrip() + block

with open(p, 'w') as f:
    f.write(src)

print("  pentest.py updated with v10 routes")
PY
fi

# 4) Install new dependencies
echo "→ Installing new Python dependencies"
if [ -f "$TARGET_DIR/venv/bin/pip" ]; then
  "$TARGET_DIR/venv/bin/pip" install -q sentence-transformers numpy || echo "  (install warning — continue)"
elif command -v pip3 >/dev/null 2>&1; then
  pip3 install -q --user sentence-transformers numpy 2>/dev/null || \
    pip3 install -q sentence-transformers numpy --break-system-packages 2>/dev/null || \
    echo "  (could not install automatically — run manually: pip install sentence-transformers numpy)"
fi

# 5) Remind the user to run migrations
cat <<EOM

╔══════════════════════════════════════════════════════╗
║  v10 OVERLAY COMPLETE                                 ║
╚══════════════════════════════════════════════════════╝

Next steps:

  1. Run DB migrations to add the new decision_logs table:
       cd $TARGET_DIR
       python -c "import asyncio; from memory.database_models import init_db; asyncio.run(init_db())"

  2. (Optional) Set NVD API key for higher CVE lookup rate limits:
       export NVD_API_KEY=your_key_here

  3. Restart your API server:
       uvicorn api.main:app --host 0.0.0.0 --port 8000

  4. Open the UI: http://your-server:7000
     - Click AUTO on the header to start the autonomous loop
     - Red-risk steps will block for your approval (as required by
       the academic project brief)
     - Watch the Decision Log tab for complete traceability

Your v9 originals are backed up to:
  $BACKUP_DIR

EOM
