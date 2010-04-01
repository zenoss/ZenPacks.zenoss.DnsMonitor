###########################################################################
#
# This program is part of Zenoss Core, an open source monitoring platform.
# Copyright (C) 2010, Zenoss Inc.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as published by
# the Free Software Foundation.
#
# For complete information please visit: http://www.zenoss.com/oss/
#
###########################################################################
from Products.Zuul.infos import ProxyProperty
from zope.interface import implements
from Products.Zuul.infos.template import RRDDataSourceInfo
from ZenPacks.zenoss.DnsMonitor.interfaces import IDnsMonitorDataSourceInfo


class DnsMonitorDataSourceInfo(RRDDataSourceInfo):
    implements(IDnsMonitorDataSourceInfo)
    timeout = ProxyProperty('timeout')
    cycletime = ProxyProperty('cycletime')
    hostname = ProxyProperty('hostname')
    dnsServer = ProxyProperty('dnsServer')
    expectedIpAddress = ProxyProperty('expectedIpAddress')

    @property
    def testable(self):
        """
        We can NOT test this datsource against a specific device
        """
        return False
    


