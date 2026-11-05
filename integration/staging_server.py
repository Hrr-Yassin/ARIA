"""Full application on the verified staging restore. Live model calls are disabled."""
import json
from pathlib import Path
from sqlalchemy.engine import make_url
from config.settings import settings
ROOT=Path(__file__).resolve().parents[1]
metadata=json.loads((ROOT/'.local-lab/upgrade-stage/metadata.json').read_text())
name=metadata['database']
if not name.startswith('aria_upgrade_') or not name.endswith('_test'): raise RuntimeError('Staging database guard refused startup')
settings.DATABASE_URL=make_url(settings.DATABASE_URL).set(database=name).render_as_string(hide_password=False)
settings.REDIS_URL=make_url(settings.REDIS_URL).set(database='15').render_as_string(hide_password=False)
settings.REPORT_OUTPUT_DIR=str(ROOT/'.local-lab/upgrade-stage/reports')
settings.BURP_COMMUNITY_ENABLED=True
settings.BURP_CONNECTOR_USER_ID=metadata['owner_before']['connector_user_id']
settings.BURP_CONNECTOR_TOKEN=(ROOT/'.local-lab/burp-runtime/connector-token').read_text().strip()
from api.main import app
from llm.validation_budget import ValidationBudget,current_budget

@app.middleware('http')
async def no_external_provider_calls(request,call_next):
    token=current_budget.set(ValidationBudget(max_calls=0,max_tokens=0))
    try: return await call_next(request)
    finally: current_budget.reset(token)
