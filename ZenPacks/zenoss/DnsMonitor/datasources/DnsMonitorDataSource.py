##############################################################################
#
# Copyright (C) Zenoss, Inc. 2017, all rights reserved.
#
# This content is made available according to terms specified in
# License.zenoss under the directory where your Zenoss product is installed.
#
##############################################################################


__doc__='''DnsMonitorDataSource.py

Defines datasource for DnsMonitor
'''

import time
import socket
from twisted.internet import defer
from twisted.names import client, error, dns
from twisted.internet.error import InvalidAddressError

from zope.component import adapts
from zope.interface import implements

from Products.ZenEvents import ZenEventClasses
from Products.Zuul.form import schema
from Products.Zuul.infos import ProxyProperty
from Products.Zuul.infos.template import RRDDataSourceInfo
from Products.Zuul.interfaces import IRRDDataSourceInfo
from Products.Zuul.utils import ZuulMessageFactory as _t

from ZenPacks.zenoss.PythonCollector.datasources.PythonDataSource \
    import PythonDataSource, PythonDataSourcePlugin

import logging
log = logging.getLogger('zen.DnsMonitor')


class DnsException(Exception):
    """
    Dns Exception.
    """

def extractIPv4Records(resolver, name, answers, level=10):
    if not level:
        return None
    if hasattr(socket, 'inet_ntop'):
        for r in answers:
            if r.name == name and r.type == dns.A6:
                return socket.inet_ntop(socket.AF_INET6, r.payload.address)
    for r in answers:
        if r.name == name and r.type == dns.A:
            return socket.inet_ntop(socket.AF_INET, r.payload.address)
    for r in answers:
        if r.name == name and r.type == dns.CNAME:
            result = extractIPv4Records(
                resolver, r.payload.name, answers, level - 1)
            if not result:
                return resolver.getHostByName(
                    str(r.payload.name), effort=level - 1)
            return result
    # No answers, but maybe there's a hint at who we should be asking about
    # this
    for r in answers:
        if r.type == dns.NS:
            from twisted.names import client
            r = client.Resolver(servers=[(str(r.payload.name), dns.PORT)])
            return r.lookupAddress(str(name)
                ).addCallback(
                lambda (ans, auth, add):
                extractIPv4Records(r, name, ans + auth + add, level - 1))


class DNSMonitor(client.Resolver):
    def _cbRecords(self, records, name, effort):
        (ans, auth, add) = records
        result = extractIPv4Records(self, dns.Name(name), ans + auth + add, effort)
        if not result:
            raise error.DNSLookupError(name)
        return result


class DnsMonitorDataSource(PythonDataSource):
    DNS_MONITOR = 'DnsMonitor'
    ZENPACKID = 'ZenPacks.zenoss.DnsMonitor'
    sourcetypes = (DNS_MONITOR,)
    sourcetype = DNS_MONITOR
    plugin_classname = (
        ZENPACKID + '.datasources.DnsMonitorDataSource.DnsMonitorDataSourcePlugin')
    timeout = 15
    eventClass = '/Status/DNS'
    hostname = '${dev/titleOrId}'
    dnsServer = ''
    expectedIpAddress = ''

    _properties = PythonDataSource._properties + (
        {'id':'hostname', 'type':'string', 'mode':'w'},
        {'id':'dnsServer', 'type':'string', 'mode':'w'},
        {'id':'expectedIpAddress', 'type':'string', 'mode':'w'},
        {'id':'timeout', 'type':'int', 'mode':'w'},
        )

    def addDataPoints(self):
        if not self.datapoints._getOb('time', None):
            self.manage_addRRDDataPoint('time')


class DnsMonitorDataSourcePlugin(PythonDataSourcePlugin):

    @classmethod
    def params(cls, datasource, context):
        params = {}

        params['hostname'] = datasource.talesEval(
            datasource.hostname, context)

        params['dnsServer'] = datasource.talesEval(
            datasource.dnsServer, context)

        params['expectedIpAddress'] = datasource.talesEval(
            datasource.expectedIpAddress, context)

        params['eventKey'] = datasource.talesEval(
            datasource.eventKey, context)

        params['eventClass'] = datasource.talesEval(
            datasource.eventClass, context)

        params['timeout'] = datasource.talesEval(
            datasource.timeout, context)

        return params

    def collect(self, config):
        ds0 = config.datasources[0]
        dnsServer = ds0.params['dnsServer']
        hostname = ds0.params['hostname']
        timeout = int(ds0.params['timeout'])
        if dnsServer:
            self.resolver = DNSMonitor(servers=[(dnsServer, 53)])
        else:
            self.resolver = DNSMonitor('/etc/resolv.conf')

        self._startTime = time.time()
        d = defer.gatherResults([self.resolver.getHostByName(
            hostname, timeout=[timeout])], consumeErrors=True)

        return d

    def onSuccess(self, results, config):
        respTime = time.time() - self._startTime
        data = self.new_data()
        perfData = {}
        perfData['time'] = respTime
        ds0 = config.datasources[0]
        hostname = ds0.params['hostname']
        expectedIpAddress = ds0.params['expectedIpAddress']

        receivedIp = results[0]
        if expectedIpAddress and expectedIpAddress != receivedIp:
            message = ("DNS CRITICAL - "
                "expected '{}' but got '{}'".format(
                    expectedIpAddress, receivedIp))
            raise DnsException(message)

        message = ("DNS OK: "
            "{:.3f} seconds response time. "
            "{} returns {}".format(respTime, hostname, receivedIp))

        log.debug('{} {}'.format(config.id, message))

        for dp in ds0.points:
            if dp.id in perfData:
                data['values'][None][dp.id] = perfData[dp.id]

        eventKey = ds0.eventKey  or 'DnsMonitor'

        data['events'].append({
            'eventKey': eventKey,
            'summary': message,
            'message': message,
            'device': config.id,
            'eventClass': ds0.eventClass,
            'severity': ZenEventClasses.Clear
        })

        return data

    def onError(self, result, config):
        respTime = time.time() - self._startTime
        data = self.new_data()
        perfData = {}
        ds0 = config.datasources[0]
        if hasattr(result.value, 'subFailure'):
            respTime, respTimeOrig = (None, respTime)
            if isinstance(result.value.subFailure.value, error.DNSServerError):
                message = "DNS WARNING - {}".format(self.resolver.pickServer()[0])
            elif isinstance(result.value.subFailure.value, InvalidAddressError):
                message = ("DNS WARNING - "
                    "Server: {} - "
                    "InvalidAddressError".format(self.resolver.pickServer()[0]))
            elif isinstance(result.value.subFailure.value, defer.TimeoutError):
                message = ("CRITICAL - Plugin timed out "
                    "while executing system call")
            elif isinstance(result.value.subFailure.value, error.DNSNameError):
                message = "Domain {} was not found by the server".format(
                    ds0.params['hostname'])
                respTime = respTimeOrig
            else:
                message = "DNS Unknown error"
        else:
            message = '{}'.format(result.getErrorMessage())
            respTime = None

        log.error('{} {}'.format(config.id, message))

        if respTime:
            perfData['time'] = respTime
            for dp in ds0.points:
                if dp.id in perfData:
                    data['values'][None][dp.id] = perfData[dp.id]

        eventKey = ds0.eventKey or 'DnsMonitor'
        data['events'].append({
            'eventKey': eventKey,
            'summary': message,
            'message': message,
            'device': config.id,
            'severity': ZenEventClasses.Error,
            'eventClass': ds0.eventClass
        })

        return data

