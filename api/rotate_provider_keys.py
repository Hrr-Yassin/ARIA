"""Re-encrypt provider keys with the primary key, using configured previous keys."""
import asyncio
from sqlalchemy import select
from memory.database_models import UserAPIKey, async_session
from llm.pool_manager import pool_manager


async def rotate_provider_keys():
    async with async_session() as db:
        rows = (await db.execute(select(UserAPIKey).with_for_update())).scalars().all()
        # A failed decrypt aborts the transaction; never mix partial commits.
        for row in rows:
            row.encrypted_key = pool_manager.encrypt_key(pool_manager.decrypt_key(row.encrypted_key))
        await db.commit()
    return len(rows)


if __name__ == '__main__':
    count = asyncio.run(rotate_provider_keys())
    print(f'Rotated {count} provider key records; no key material was displayed.')
