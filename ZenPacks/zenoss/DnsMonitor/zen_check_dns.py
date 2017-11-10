#!/opt/zenoss/bin/python
##############################################################################
# 
# Copyright (C) Zenoss, Inc. 2017, all rights reserved.
# 
# This content is made available according to terms specified in
# License.zenoss under the directory where your Zenoss product is installed.
# 
##############################################################################

import argparse
import os
import time
from twisted.internet import defer
from twisted.names import client
from twisted.internet import reactor
from twisted.internet.defer import Deferred

##############################################################################
# `check_dns` output examples:
# 
# (zenoss) [zenoss@0f473b0925b5 ~]$ /usr/lib64/nagios/plugins/check_dns -H ip-10-111-23-85.zenoss.loc
# DNS OK: 0.049 seconds response time. ip-10-111-23-85.zenoss.loc returns 10.111.23.85|time=0.048760s;;;0.000000
#
# (zenoss) [zenoss@0f473b0925b5 ~]$ python zen_check_dns.py -H ip-10-111-23-85.zenoss.loc
# DNS OK: 0.042 seconds response time. ip-10-111-23-85.zenoss.loc returns 10.111.23.85|time=0.041691s;;;0.000000
#
# [root@2249ddc9bace /]# /usr/lib64/nagios/plugins/check_dns -H ip-10-111-23-85.zenoss.loc
# DNS OK: 0.045 seconds response time. ip-10-111-23-85.zenoss.loc returns 10.111.23.85|time=0.044544s;;;0.000000
# 
# [root@2249ddc9bace /]# /usr/lib64/nagios/plugins/check_dns -H ip-10-111-23-85.zenoss.loc -a 10.111.23.85
# DNS OK: 0.043 seconds response time. ip-10-111-23-85.zenoss.loc returns 10.111.23.85|time=0.042731s;;;0.000000
#
# [root@2249ddc9bace /]# /usr/lib64/nagios/plugins/check_dns -H ip-10-111-23-85.zenoss.loc -a 10.111.23.86
# DNS CRITICAL - expected '10.111.23.86' but got '10.111.23.85'
#
# [root@2249ddc9bace /]# /usr/lib64/nagios/plugins/check_dns -H ip-10-111-23-85.zenoss.x
# DNS WARNING -         10.87.113.13
#
# [root@2249ddc9bace /]# /usr/lib64/nagios/plugins/check_dns -s 8.8.8.8 -H ip-10-111-23-85.zenoss.loc
# DNS WARNING -         8.8.8.8
##############################################################################


OK_MESSAGE = "DNS OK: {:.3f} seconds response time. {} returns {}|time={:.6f}s;;;0.000000"
CRITICAL_MESSAGE = "DNS CRITICAL - expected {} but got {}"
WARNING_MESSAGE = "DNS WARNING -        {}"

EXIT_CODES = {
    "CRITICAL": 2,
    "WARNING": 1,
    "OK": 0,
}

class CheckDNS(object):

    def __init__(self, hostname, dnsServer, expectedIpAddress):
        self._hostname = hostname
        self._dnsServer = dnsServer
        self._expectedIpAddress = expectedIpAddress
        self._startTime = time.time()
        self._finishedDeferred = Deferred()

    def run(self):

        if self._dnsServer:
            resolver = client.createResolver(servers=[(self._dnsServer, 53)])
        else:
            resolver = client.Resolver('/etc/resolv.conf')

        d = defer.gatherResults([resolver.lookupAddress(
            self._hostname)], consumeErrors=True)

        d.addCallback(self._gotResponse)
        d.addErrback(self._gotError, resolver.pickServer()[0])

        return self._finishedDeferred

    def _gotResponse(self, response):
        respTime = time.time() - self._startTime
        answers, authority, additional = response[0]
        x = answers[0]
        hostname = x.name.name
        receivedIp = x.payload.dottedQuad()

        if self._expectedIpAddress and self._expectedIpAddress != receivedIp:
            level = "CRITICAL"
            message = CRITICAL_MESSAGE.format(self._expectedIpAddress, receivedIp)
            self._finishedDeferred.callback((level, message))

        level = "OK"
        message = OK_MESSAGE.format(respTime, hostname, receivedIp, respTime)
        self._finishedDeferred.callback((level, message))

    def _gotError(self, failure, dnsServer=None):
        # if error.DNSNameError:
        level = "WARNING"
        message = WARNING_MESSAGE.format(dnsServer)
        self._finishedDeferred.callback((level, message))
        # else: raise some exception

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-H", dest="hostname")
    parser.add_argument("-s", dest="dnsServer")
    parser.add_argument("-a", dest="expectedIpAddress")

    args = parser.parse_args()
    
    kwargs = {}
    for attrName in dir(args):
        if not attrName.startswith("_"):
            kwargs[attrName] = getattr(args, attrName, None)
    checkDNS = CheckDNS(**kwargs)
    d = checkDNS.run()
    d.addCallback(_done)
    reactor.run()

def _done(result):
    level, message = result
    print message
    reactor.stop()
    os._exit(EXIT_CODES[level])

if __name__ == "__main__":
    main()

