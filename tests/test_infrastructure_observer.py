"""Supervision must report losses/gaps without replaying or fabricating uptime."""
import copy
import unittest

from deploy.lab.observe_infrastructure import assess


class InfrastructureObserverTests(unittest.TestCase):
    def sample(self):
        return {'boot_id':'boot','monotonic_seconds':100,'boottime_seconds':100,
            'units':{'aria.service':{'ActiveState':'active','NRestarts':'0'},
                     'aria-lab-dependencies.service':{'ActiveState':'active'}},
            'containers':{'aria-postgres':{'running':True},'aria-redis':{'running':True}},
            'readiness':{'http_status':200,'database':True,'cache':True},'observation_errors':[]}

    def test_healthy_point_never_claims_continuous_availability_or_replay(self):
        result=assess(self.sample())
        self.assertEqual(result['status'],'READY')
        self.assertFalse(result['continuous_availability_verified'])
        self.assertEqual(result['automatic_restart_dispatch_replay_operations'],0)
        self.assertIsNone(result['measured_suspended_since_previous_seconds'])

    def test_required_database_or_controller_loss_is_unavailable(self):
        for section,key,value in (('readiness','database',False),('readiness','http_status',503)):
            sample=self.sample();sample[section][key]=value
            with self.subTest(key=key):self.assertEqual(assess(sample)['status'],'UNAVAILABLE')
        for key in ('aria-postgres','aria.service'):
            sample=self.sample()
            if key=='aria-postgres':sample['containers'][key]['running']=False
            else:sample['units'][key]['ActiveState']='failed'
            with self.subTest(key=key):self.assertEqual(assess(sample)['status'],'UNAVAILABLE')

    def test_optional_cache_loss_is_degraded_not_fabricated_database_outage(self):
        sample=self.sample();sample['readiness']['cache']=False
        result=assess(sample)
        self.assertEqual(result['status'],'DEGRADED')
        self.assertEqual(result['reason_codes'],['optional_cache_unavailable'])

    def test_incomplete_observation_does_not_report_healthy(self):
        sample=self.sample();sample['observation_errors']=[{'stage':'containers','error_type':'TimeoutExpired'}]
        self.assertEqual(assess(sample)['status'],'UNAVAILABLE')

    def test_restart_counters_are_compared_only_within_same_boot(self):
        previous=self.sample();previous['units']['aria.service']['NRestarts']='214'
        sample=self.sample();sample['boot_id']='new-boot'
        result=assess(sample,previous)
        self.assertEqual(result['status'],'READY');self.assertFalse(result['same_boot_as_previous'])
        previous=self.sample();sample=self.sample();sample['units']['aria.service']['NRestarts']='1'
        self.assertIn('controller_restart_observed',assess(sample,previous)['reason_codes'])

    def test_measured_sleep_is_separate_from_active_time_and_availability(self):
        previous=self.sample();sample=copy.deepcopy(previous)
        sample.update(monotonic_seconds=130,boottime_seconds=7330)
        result=assess(sample,previous)
        self.assertEqual(result['measured_suspended_since_previous_seconds'],7200)
        self.assertEqual(result['status'],'READY');self.assertFalse(result['continuous_availability_verified'])
