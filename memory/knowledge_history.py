"""Reconstruct the retained team projection at a recorded ledger sequence."""
import re
from datetime import datetime

from fastapi import HTTPException
from sqlalchemy import func, select

from memory.database_models import DecisionLog, PentestSession, async_session
from memory.team_tasks import public

MAX_RECORDS = 2_000
SCALARS = {
    'tasks': ('title', 'objective', 'state', 'owner_role', 'revision', 'reason', 'finished_at'),
    'evidence': ('source_kind', 'source_id', 'provenance', 'trust', 'digest', 'source_timestamp', 'cataloged_at'),
    'knowledge': ('text', 'kind', 'disposition', 'actor', 'uncertainty'),
    'verification_findings': ('title', 'state', 'revision', 'smallest_missing_validation', 'specialist_task_id'),
    'research_hypotheses': ('title', 'state', 'revision', 'uncertainty', 'finding_id'),
}
REFERENCES = {
    'tasks': ('dependencies', 'evidence_inputs'),
    'evidence': (),
    'knowledge': ('evidence_references', 'contradicts'),
    'verification_findings': ('evidence_references',),
    'research_hypotheses': ('supporting_evidence', 'evidence_references'),
}
CONTROL_REFERENCES = ('evidence_references', 'negative_control_references', 'ownership_references', 'permission_references')
IDENTIFIER = re.compile(r'[A-Za-z0-9._:-]{1,100}')


def saved_time(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        timestamp = datetime.fromisoformat(value)
        return timestamp.isoformat() if timestamp.utcoffset() is not None else None
    except (OverflowError, ValueError):
        return None


def selected_fields(row: dict, scalars: tuple[str, ...] = (), refs: tuple[str, ...] = ()) -> dict:
    data = {}
    for key in scalars:
        value = row.get(key)
        if isinstance(value, str):
            data[key] = public(value)[:2_000]
        elif type(value) is int and 0 <= value <= 2_147_483_647:
            data[key] = value
    for key in refs:
        value = row.get(key)
        if isinstance(value, list):
            data[key] = list(dict.fromkeys(ref for ref in value[:100]
                                         if isinstance(ref, str) and IDENTIFIER.fullmatch(ref)))
    return data


def graph_revision(collection: str, entity_id: str, data: object, first: object, last: object) -> dict | None:
    if not isinstance(entity_id, str) or not IDENTIFIER.fullmatch(entity_id) or not isinstance(data, dict):
        return None
    if collection == 'knowledge' and data.get('kind') not in ('observation', 'hypothesis'):
        return None
    result = {'id': entity_id, 'first_recorded_at': saved_time(first), 'recorded_at': saved_time(last),
              **selected_fields(data, SCALARS[collection], REFERENCES[collection])}
    if collection == 'research_hypotheses' and isinstance(data.get('uncertainty'), list):
        result['uncertainty'] = [public(note)[:2_000] for note in data['uncertainty'][:20] if isinstance(note, str)]
    if collection == 'tasks' and isinstance(data.get('result'), dict):
        result['result'] = selected_fields(data['result'], refs=('evidence_references',))
    if collection == 'verification_findings':
        for stage in ('test', 'reproduction'):
            if isinstance(data.get(stage), dict):
                result[stage] = selected_fields(data[stage], refs=CONTROL_REFERENCES)
        for stage in ('human_review', 'human_signoff'):
            if isinstance(data.get(stage), dict):
                result[stage] = selected_fields(data[stage], ('reason', 'revision'))
    return result


async def exploration_checkpoint(sid: str, owner: str, at: int) -> dict:
    metadata = DecisionLog.metadata_
    sequence = metadata['sequence'].as_integer()
    timestamp = metadata['timestamp'].as_string()
    collection = metadata['collection'].as_string()
    entity = metadata['entity_id'].as_string()
    identity = DecisionLog.id
    owned = (
        PentestSession.user_id == owner, DecisionLog.user_id == owner, DecisionLog.session_id == sid,
        DecisionLog.decision_type == 'team_event', sequence.between(1, at),
    )
    join = PentestSession.id == DecisionLog.session_id
    async with async_session() as db:
        anchors = (await db.execute(select(metadata['id'].as_string(), timestamp).select_from(DecisionLog)
            .join(PentestSession, join).where(*owned, sequence == at).limit(2))).all()
        if not anchors:
            raise HTTPException(404, 'Team checkpoint unavailable in this engagement')
        if len(anchors) != 1:
            raise HTTPException(409, 'The saved checkpoint sequence is ambiguous')
        event_id, recorded = anchors[0]
        count, unique = (await db.execute(select(func.count(), func.count(func.distinct(sequence)))
            .select_from(DecisionLog).join(PentestSession, join).where(*owned))).one()
        partition = (collection, entity)
        ranked = (select(collection.label('collection'), entity.label('entity'), metadata['data'].label('data'),
            timestamp.label('last_recorded'), sequence.label('sequence'), identity.label('row_id'),
            func.first_value(timestamp).over(partition_by=partition, order_by=(sequence, identity)).label('first_recorded'),
            func.row_number().over(partition_by=partition, order_by=(sequence.desc(), identity.desc())).label('rank'))
            .select_from(DecisionLog).join(PentestSession, join).where(*owned, collection.in_(SCALARS)).subquery())
        data = (await db.execute(select(ranked).where(ranked.c.rank == 1)
            .order_by(ranked.c.sequence.desc(), ranked.c.row_id.desc()).limit(MAX_RECORDS + 1))).mappings().all()

    records: dict[str, list[dict]] = {collection: [] for collection in SCALARS}
    rejected = 0
    for stored in data[:MAX_RECORDS]:
        kind = stored['collection']
        record = graph_revision(kind, stored['entity'], stored['data'], stored['first_recorded'], stored['last_recorded'])
        if record is not None:
            records[kind].append(record)
        else:
            rejected += 1
    return {'schema_version': 'aria.mission.exploration-checkpoint.v1', 'session_id': sid, 'sequence': at,
            'event_id': event_id if isinstance(event_id, str) and IDENTIFIER.fullmatch(event_id) else None,
            'timestamp': saved_time(recorded), 'event_gap': unique != at or count != unique,
            'truncated': len(data) > MAX_RECORDS, 'rejected_records': rejected, 'records': records}
