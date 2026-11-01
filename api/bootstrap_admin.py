"""Explicit administrator provisioning: python -m api.bootstrap_admin."""
import asyncio
import getpass
from sqlalchemy import select
from api.auth import hash_password
from memory.database_models import User, UserRole, SkillLevel, async_session


async def create_admin(username: str, password: str):
    if not username.strip() or len(password) < 14:
        raise ValueError('A username and a password of at least 14 characters are required')
    async with async_session() as db:
        existing = (await db.execute(select(User).where(User.username == username))).scalar_one_or_none()
        if existing:
            raise ValueError('User already exists; bootstrap does not alter existing users')
        db.add(User(username=username, password_hash=hash_password(password),
                    role=UserRole.ADMIN, skill_level=SkillLevel.EXPERT, display_name=username))
        await db.commit()


def main():
    username = input('Administrator username: ').strip()
    password = getpass.getpass('Administrator password: ')
    if password != getpass.getpass('Confirm password: '):
        raise SystemExit('Passwords do not match')
    asyncio.run(create_admin(username, password))
    print('Administrator created')


if __name__ == '__main__':
    main()
