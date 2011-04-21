###########################################################################
#
# This program is part of Zenoss Core, an open source monitoring platform.
# Copyright (C) 2007, Zenoss Inc.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 or (at your
# option) any later version as published by the Free Software Foundation.
#
# For complete information please visit: http://www.zenoss.com/oss/
#
###########################################################################

__doc__='''DnsMonitorDataSource.py

Defines datasource for DnsMonitor
'''

import Products.ZenModel.RRDDataSource as RRDDataSource
from Products.ZenModel.ZenPackPersistence import ZenPackPersistence
from AccessControl import ClassSecurityInfo, Permissions
from Products.ZenUtils.ZenTales import talesCompile, getEngine
from Products.ZenUtils.Utils import binPath


class DnsMonitorDataSource(ZenPackPersistence, RRDDataSource.RRDDataSource):
    
    DNS_MONITOR = 'DnsMonitor'

    ZENPACKID = 'ZenPacks.zenoss.DnsMonitor'

    sourcetypes = (DNS_MONITOR,)
    sourcetype = DNS_MONITOR

    timeout = 15
    eventClass = '/Status/DNS'

    hostname = '${dev/id}'
    dnsServer = ''
    expectedIpAddress = ''

    _properties = RRDDataSource.RRDDataSource._properties + (
        {'id':'hostname', 'type':'string', 'mode':'w'},
        {'id':'dnsServer', 'type':'string', 'mode':'w'},
        {'id':'expectedIpAddress', 'type':'string', 'mode':'w'},
        {'id':'timeout', 'type':'int', 'mode':'w'},
        )
        
    _relations = RRDDataSource.RRDDataSource._relations + (
        )


    factory_type_information = ( 
    { 
        'immediate_view' : 'editDnsMonitorDataSource',
        'actions'        :
        ( 
            { 'id'            : 'edit',
              'name'          : 'Data Source',
              'action'        : 'editDnsMonitorDataSource',
              'permissions'   : ( Permissions.view, ),
            },
        )
    },
    )

    security = ClassSecurityInfo()


    def __init__(self, id, title=None, buildRelations=True):
        RRDDataSource.RRDDataSource.__init__(self, id, title, buildRelations)
        #self.addDataPoints()


    def getDescription(self):
        if self.sourcetype == self.DNS_MONITOR:
            return self.hostname
        return RRDDataSource.RRDDataSource.getDescription(self)


    def useZenCommand(self):
        return True


    def getCommand(self, context):
        parts = [binPath('check_dns')]
        if self.hostname:
            parts.append('-H "%s"' % self.hostname)
        if self.dnsServer:
            parts.append('-s "%s"' % self.dnsServer)
        if self.expectedIpAddress:
            parts.append('-a %s' % self.expectedIpAddress)
        cmd = ' '.join(parts)
        cmd = RRDDataSource.RRDDataSource.getCommand(self, context, cmd)
        return cmd


    def checkCommandPrefix(self, context, cmd):
        return cmd


    def addDataPoints(self):
        if not hasattr(self.datapoints, 'time'):
            self.manage_addRRDDataPoint('time')


    def zmanage_editProperties(self, REQUEST=None):
        '''validation, etc'''
        if REQUEST:
            # ensure default datapoint didn't go away
            self.addDataPoints()
            # and eventClass
            if not REQUEST.form.get('eventClass', None):
                REQUEST.form['eventClass'] = self.__class__.eventClass
        return RRDDataSource.RRDDataSource.zmanage_editProperties(self, REQUEST)


