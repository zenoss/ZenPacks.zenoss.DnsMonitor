##############################################################################
#
# Copyright (C) Zenoss, Inc. 2017, all rights reserved.
#
# This content is made available according to terms specified in
# License.zenoss under the directory where your Zenoss product is installed.
#
##############################################################################

import time
from twisted.names.error import DNSNameError

from Products.ZenTestCase.BaseTestCase import BaseTestCase
from ZenPacks.zenoss.DnsMonitor.datasources.DnsMonitorDataSource \
                        import DnsMonitorDataSourcePlugin, DnsException


class Dummy(): pass


class DummyConfig():
    def __init__(self, datasources):
        self.id = 'testdevice'
        self.datasources = datasources


class DummyDataSource():
    def __init__(self, expectedIpAddress):
        self.params = {
            'expectedIpAddress': expectedIpAddress,
            'hostname': 'example.com'
            }
        self.severity = 3
        self.points = []
        self.eventKey = ''
        self.eventClass = '/Status/DNS'


class DummyAnswer():
    def __init__(self, receivedIP):
        self.name = Dummy()
        self.name.name = 'example.com'
        self.payload = Dummy()
        self.payload.dottedQuad = lambda: receivedIP


class DummyErrorResult():
    def __init__(self, errorMessage, dnsError=False):
        self.value = None
        if dnsError:
            self.value = Dummy()
            self.value.subFailure = Dummy()
            self.value.subFailure.value = DNSNameError(errorMessage)
        self.getErrorMessage = lambda: errorMessage


class TestDnsMonitorDataSourcePlugin(BaseTestCase):

    def afterSetUp(self):
        super(TestDnsMonitorDataSourcePlugin, self).afterSetUp()
        self.plugin = DnsMonitorDataSourcePlugin()
        self.plugin._startTime = time.time()
        self.plugin.resolver = Dummy()
        self.plugin.resolver.pickServer = lambda: ('testDnsServer', 53)
        
    def createResponse(self, IP):
        return [[[DummyAnswer(IP)], None, None]]

    def test_plugin(self):
        ds = DummyDataSource('1.1.1.1')
        config = DummyConfig([ds])
     
        # Test clear events if no DNS errors

        response = self.createResponse('1.1.1.1')
        testEvent = {
            'severity': 0,
            'eventClass': '/Status/DNS',
            'eventKey': 'DnsMonitor',
        }
        
        pluginEvent = self.plugin.onSuccess(
            response, config).get('events')[0]

        self.assertTrue(set(testEvent.items()).issubset(
            set(pluginEvent.items())))

        # Test DnsException if expected IP address 
        # is not equal to received IP address.

        response = self.createResponse('2.2.2.2')
        self.assertRaises(DnsException, lambda: self.plugin.onSuccess(
            response, config).get('events'))

        # Test events on Dns errors

        self.assertIn(
            {'severity': 4, 
            'summary': "Domain example.com was not found by the server",
            'eventKey': 'DnsMonitor',
            'device': 'testdevice',
            'message': "Domain example.com was not found by the server",
            'eventClass': '/Status/DNS'},
            self.plugin.onError(
                DummyErrorResult('Host not found', dnsError=True), config).get('events'))

        # Test error events

        self.assertIn(
            {'severity': 4,
            'summary': 'test',
            'eventKey': 'DnsMonitor',
            'device': 'testdevice',
            'message': 'test',
            'eventClass': '/Status/DNS'},
            self.plugin.onError(
                DummyErrorResult('test'), config).get('events'))

        
def test_suite():
    from unittest import TestSuite, makeSuite
    suite = TestSuite()
    suite.addTest(makeSuite(TestDnsMonitorDataSourcePlugin))
    return suite

