from dataclasses import asdict, replace
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import HTTPException
from memory.execution_authorization import SQLAuthorizationStore, Proposal, authoritative_context
from tests.support import OfflineCase


class StoreTests(OfflineCase):
    def database(self, rows):
        db = AsyncMock()
        results=[]
        for row in rows:
            result=MagicMock()
            result.scalar_one_or_none.return_value=row
            results.append(result)
        db.execute.side_effect=results
        db.add=MagicMock()
        factory=MagicMock()
        factory.return_value.__aenter__=AsyncMock(return_value=db)
        factory.return_value.__aexit__=AsyncMock(return_value=False)
        return db,factory

    async def test_sql_transition_locks_compares_and_commits_before_return(self):
        original=Proposal('action','session','owner','nmap 192.0.2.1','nmap','orange','hash',9999999999,'authorized')
        row=SimpleNamespace(metadata_=asdict(original))
        db,factory=self.database([row])
        updated=replace(original,status='consumed',revision=1)
        with patch('memory.execution_authorization.async_session',factory):
            self.assertTrue(await SQLAuthorizationStore().transition(original,updated))
        self.assertEqual(row.metadata_['status'],'consumed')
        self.assertTrue(db.execute.await_args.args[0]._for_update_arg is not None)
        db.commit.assert_awaited_once()
        db.add.assert_called_once()

    async def test_sql_transition_refuses_stale_approval(self):
        proposal=Proposal('action','session','owner','nmap 192.0.2.1','nmap','orange','hash',9999999999,'authorized')
        db,factory=self.database([SimpleNamespace(metadata_=asdict(replace(proposal,status='consumed')))])
        with patch('memory.execution_authorization.async_session',factory):
            self.assertFalse(await SQLAuthorizationStore().transition(proposal,replace(proposal,status='consumed')))
        db.commit.assert_not_awaited()

    async def test_authoritative_context_checks_active_database_identity_and_owner(self):
        for active, role, owner, status, permitted in [(True,'pentester','owner','active',True),
                (False,'admin','owner','active',False),(True,'pentester','other','active',False),
                (True,'admin','other','active',True),(True,'admin',None,'active',False),
                (True,'pentester','owner','archived',False)]:
            with self.subTest(active=active,role=role,owner=owner,status=status):
                user=SimpleNamespace(id='owner',is_active=active,role=SimpleNamespace(value=role))
                session=SimpleNamespace(user_id=owner,status=SimpleNamespace(value=status),scope={'targets':['192.0.2.1']},attack_mode='lab')
                db,factory=self.database([user,session])
                with patch('memory.execution_authorization.async_session',factory):
                    if permitted:
                        self.assertEqual((await authoritative_context('owner','session'))['owner_id'],owner)
                    else:
                        with self.assertRaises(HTTPException):
                            await authoritative_context('owner','session')

    async def test_authoritative_context_requires_both_identity_and_engagement(self):
        with patch('memory.execution_authorization.async_session') as factory:
            with self.assertRaises(HTTPException):
                await authoritative_context('', 'session')
            factory.assert_not_called()

    async def test_socket_uses_live_role_and_denies_disabled_or_missing_accounts(self):
        from api.auth import authenticate_socket_token, create_token
        token=create_token('owner','owner','admin','expert')
        for active in [True, False, None]:
            user = SimpleNamespace(id='owner',username='owner',is_active=active,
                                   role=SimpleNamespace(value='pentester'),skill_level=SimpleNamespace(value='expert')) if active is not None else None
            db,factory=self.database([user])
            with patch('api.auth.async_session',factory):
                if active:
                    self.assertEqual((await authenticate_socket_token(token)).role, 'pentester')
                else:
                    with self.assertRaises(HTTPException):
                        await authenticate_socket_token(token)
