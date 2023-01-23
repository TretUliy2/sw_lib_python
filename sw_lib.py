#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import division
import netsnmp
import sys
import time
import psycopg2
from collections import OrderedDict
import struct

class sw(object):
    """Developed for querying switches about ports status and erros 
    Should return Dictionary of all needed things"""
    def __init__(self, ip, community):
        self.ip = ip
        self.password = community


    def getPortAdminStatus(self, port):
        # Admin status base oid
        base = ".1.3.6.1.2.1.2.2.1.7"
        oid = "%s.%s" % (base, port)
        var = netsnmp.Varbind(oid) 
        res = netsnmp.snmpget(var, Version = 2,  DestHost = self.ip, Community=self.password) 
        return res[0]
        
    def filterPortType(self, port):
        base = ".1.3.6.1.2.1.2.2.1.3"
        var = netsnmp.VarList(base)
        res = netsnmp.snmpwalk(var, Version = 2,  DestHost = self.ip, Community=self.password)
        for oid in var:
            if oid.val in ['117', '6', '94']:
                #print "oid.iid = %s oid.val = %s != 117" % (oid.iid, oid.val)
                del port[oid.iid]

    def getPortType(self):
        port = dict()
        base = ".1.3.6.1.2.1.2.2.1.3"
        var = netsnmp.VarList(base)
        res = netsnmp.snmpwalk(var, Version = 2,  DestHost = self.ip, Community=self.password)
        for oid in var:
            if oid.val in ['117', '6', '94']:
                port[oid.iid] = oid.val
        return port

    def getPortStatus(self, port):
        # oper status base oid
        base = ".1.3.6.1.2.1.2.2.1.8"
        oid = "%s.%s" % (base, port)
        var = netsnmp.Varbind(oid)
        res = netsnmp.snmpget(var, Version = 2,  DestHost = self.ip, Community=self.password) 
        return res[0]

    def getPortSpeed(self, port):
        # Speed base oid
        base = ".1.3.6.1.2.1.2.2.1.5"
        oid = "%s.%s" %(base, port)
        var = netsnmp.Varbind(oid)
        res = netsnmp.snmpget(var, Version = 2,  DestHost = self.ip, Community=self.password)
        return res[0]

    def getPortDescr(self, port):
        # Get ports Description
        base = ".1.3.6.1.2.1.2.2.1.2"
        oid = "%s.%s" % (base, port)
        var  = netsnmp.Varbind(oid)
        res = netsnmp.snmpget(var, Version = 2,  DestHost = self.ip, Community=self.password)
        return res[0]
    
    def getPortAlias(self, port):
        # Get ports Description
        base = ".1.3.6.1.2.1.31.1.1.1.18"
        oid = "%s.%s" % (base, port)
        var  = netsnmp.Varbind(oid)
        res = netsnmp.snmpget(var, Version = 2,  DestHost = self.ip, Community=self.password)
        return res[0]

    def getPortInerrors(self, port):
        # IfInErrors Base oid
        base = ".1.3.6.1.2.1.2.2.1.14"
        oid = "%s.%s" % (base, port)
        var  = netsnmp.Varbind(oid)
        res = netsnmp.snmpget(var, Version = 2,  DestHost = self.ip, Community=self.password)
        return res[0]

    def getPortVlan(self, port):
        # BRIDGE-MIB::dot1dBridge.7.1.4.5.1.1 
        base = ".1.3.6.1.2.1.17.7.1.4.5.1.1"
        oid = "%s.%s" % (base, port)
        var =  netsnmp.Varbind(oid)
        res = netsnmp.snmpget(var, Version = 2,  DestHost = self.ip, Community=self.password)
        return res[0]

    def getVlanUntaggedPorts(self, vlan):
        oid = ".1.3.6.1.2.1.17.7.1.4.3.1.4.%s" % (vlan, )
        var = netsnmp.Varbind(oid)
        res = netsnmp.snmpget(var, Version = 2, DestHost = self.ip, Community = self.password)
        resHex = "".join(["%02x" % ord(c) for c in var.val])
        return int(resHex, 16)

    def getVlanTaggedPorts(self, vlan):
        oid = ".1.3.6.1.2.1.17.7.1.4.3.1.2.%s" % (vlan, )
        var = netsnmp.Varbind(oid)
        res = netsnmp.snmpget(var, Version = 2, DestHost = self.ip, Community = self.password)
        resHex = "".join(["%02x" % ord(c) for c in var.val])
        return int(resHex, 16)
    
    def port2bin_32(self, port):
        return pow(2, 32 - int(port))
    
    def port2bin_56(self, port):
        return pow(2, 56 - int(port))

    def port2bin_64(self, port):
        return pow(2, 64 - int(port))
        
    def addVlanUntagged(self, port, vlan):
        # BRIDGE-MIB::dot1dBridge.7.1.4.5.1.1 
        # .1.3.6.1.2.1.17.7.1.4.3.1.2.xxxx -  Q-BRIDGE-MIB::dot1qVlanStaticEgressPorts (Tagged ports in hex)
        # .1.3.6.1.2.1.17.7.1.4.3.1.4.xxxx -  Q-BRIDGE-MIB::dot1qVlanStaticUntaggedPorts (Untagged ports in hex)
        # to add ports 14 untagged into existing vlan85 on des3526 port 11 already untagged in vlan85
        # port 11 - 0020 0000
        # port 14 - 0004 0000
        # snmpset -v2c -c private 192.168.40.21 .1.3.6.1.2.1.17.7.1.4.3.1.2.85 x 00240000 .1.3.6.1.2.1.17.7.1.4.3.1.4.85 x 00240000
        oidTagged = ".1.3.6.1.2.1.17.7.1.4.3.1.2.%s" % (vlan,)
        oidUntagged = ".1.3.6.1.2.1.17.7.1.4.3.1.4.%s" % (vlan,)

        var =  netsnmp.VarList()
        session = netsnmp.Session(Version = 2, DestHost=self.ip, Community=self.password)
        curVlanPorts = sw.getVlanTaggedPorts(self, vlan)
        newPortMask = sw.port2bin_32(self, port)
        newVlanPorts = curVlanPorts|newPortMask
        var.append(netsnmp.Varbind(tag = oidTagged, 
                                   val = struct.pack(">I", newVlanPorts)))
        var.append(netsnmp.Varbind(tag = oidUntagged, 
                                   val = struct.pack(">I", newVlanPorts)))
        res = 0
        try:
            res = session.set(var)
        except:
            print("Error has occured while snmpset operation: %s !" % session.ErrorStr)
        
        return res


    
    def addVlanTagged(self, port, vlan):
        oidTagged = ".1.3.6.1.2.1.17.7.1.4.3.1.2.%s" % (vlan,)
        
        var =  netsnmp.VarList()
        session = netsnmp.Session(Version = 2, DestHost = self.ip, Community = self.password)
        curVlanPorts = sw.getVlanTaggedPorts(self, vlan)
        newPortMask = sw.port2bin_32(self, port)
        newVlanPorts = curVlanPorts|newPortMask
        var.append(netsnmp.Varbind(tag = oidTagged, 
                                   val = struct.pack(">I", newVlanPorts)))
        res = session.set(var)
        return res
  
    def setPortAdminUp(self, port):
        # Admin status base oid
        base = ".1.3.6.1.2.1.2.2.1.7"
        oid = "%s.%s" % (base, port)
        var = netsnmp.Varbind(oid) 
        var.val = 1 # 1 - up 2 - down
       
        try:
            res = netsnmp.snmpset(var, Version = 2,  DestHost = self.ip, Community=self.password) 
        except:
             print("(%s) : Error has occured while doing it" % (__name__) )

    def setPortAdminDown(self, port):
        # Admin status base oid
        base = ".1.3.6.1.2.1.2.2.1.7"
        oid = "%s.%s" % (base, port)
        var = netsnmp.Varbind(oid) 
        var.val = 2
        try:
            res = netsnmp.snmpset(var, Version = 2,  DestHost = self.ip, Community=self.password) 
        except (res.ErrorStr, message):
            print("Error: %s" % (message, ))
    
    def setPortDescr(self, port, descr):
        # Set ports Description
        base = ".1.3.6.1.2.1.2.2.1.2"
        oid = "%s.%s" % (base, port)
        var = netsnmp.Varbind(oid) 
        var.val = descr
        try:
            print("Trying to set description")
            res = netsnmp.snmpset(var, Version = 2,  DestHost = self.ip, Community=self.password)
            if not res:
                print("Error has occured var.tag = %s var.type = %s var.val = %s" % (var.tag, var.type, var.val))
                return False 
            else:
                return True
        except:
            print("Error: Exception has occured var = %s" % (var, ))
            return False
        
    def setPortAlias(self, port, descr):
        # Set ports Alias
        base = ".1.3.6.1.2.1.31.1.1.1.18"
        oid = "%s.%s" % (base, port)
        var = netsnmp.Varbind(oid) 
        var.val = descr
        try:
            res = netsnmp.snmpset(var, Version = 2,  DestHost = self.ip, Community=self.password) 
        except (res.ErrorStr, message):
            print("Error: %s" % (message, ))

    def getPortMac(self, port):
        base = ".1.3.6.1.2.1.17.7.1.2.2.1.2"
        oid = base
        var = netsnmp.VarList(oid)
        try:
            res = netsnmp.snmpwalk(var, Version = 2, DestHost = self.ip, Community=self.password, UseNumeric=True)
        except (res.ErrorStr, message):
            print("Error: %s " % (message, ))

        mac_list = []
        for oid in var:
            if int(oid.val) != int(port):
                next
            else:
                oid.tag = "%s.%s" % (oid.tag, oid.iid)
                tmp = oid.tag[28:].split('.')
                vlan = tmp[0]
                mac = ':'.join(['{:02x}'.format(int(x)) for x in tmp[1:]])
                mac_list.append({'vlan': vlan, 'mac': mac})
                #print "vlan = %s, mac = %s, port = %s" % (vlan, mac, oid.val)
                #print "oid = %s iid = %s oid_conv = %s value = %s "  % (oid.tag, oid.iid,  oid.tag[28:].split('.'), oid.val)

        return mac_list
                

    def getPortInfo(self):
        port_info = []
        prts = sw.getPortType(self)
        for port in sorted(prts, key=lambda x: int(x)):
            port_info[port] = {\
                    'port' : port,\
                    'descr' : sw.getPortDescr(self, port),\
                    'status': sw.getPortStatus(self, port), \
                    'vlanid': sw.getPortVlan(self, port), \
                    'inerrors' : sw.getPortInerrors(self, port)\
                    }
            speed = sw.getPortSpeed(self, port)
            if int(speed) >= 1000000000:
                speed = "%sG" % (int(speed)/1000000000, )
            else:
                speed = "%.2dM" % (int(speed)/1000000, )
            
            port_info[port]['speed'] = speed
            admin_status = sw.getPortAdminStatus(self, port)
            
            if admin_status == '1':
                admin_status = 'UP'
            elif admin_status == '2':
                admin_status = 'DOWN'
            
            port_info[port]['admin_status'] = admin_status
        
        try:
            res = []
            con = psycopg2.connect(host='192.168.17.2', database='switches', user='demiurg', password='rb,thgfyr')
            SQL = "select podp.port, podp.descr from podp, sw where sw.id = podp.id_sw and ip_address = %s order by podp.port"
            cur = con.cursor()
            cur.execute(SQL, (self.ip, ))
            res = cur.fetchall()
        
        except (psycopg2.DatabaseError, e):
            print("Error: %s" % e)
            pass
        
        finally:
            cur.close()
            con.close()
            
        for item in res:
            port_info[str(item[0])]['descr'] = item[1]

        return port_info


class dlink(sw):
    """Special class for dlink switches"""
    
    def setPortDescr(self, port, descr):
        base = ".1.3.6.1.2.1.31.1.1.1.18"
        oid = "%s.%s" % (base, port)
        var = netsnmp.Varbind(oid)
        var.val = descr
        
        try:
            res = netsnmp.snmpset(var, Version = 2, DestHost = self.ip, Community = self.password)
            if not res:
                return False
            else:
                return True
        
        except:
            print("Error: Exception has occured while setting description")
            return False
        
        
        
    def setCableDiagAction(self, port):
        # set dlink cable diagnostics start
        # swEtherCableDiagAction.1 .1.3.6.1.4.1.171.12.58.1.1.1.12.1
        base = ".1.3.6.1.4.1.171.12.58.1.1.1.12"
        oid = "%s.%s" % (base, port)
        var = netsnmp.Varbind(oid)
        var.val = 1 # 1 to start cable diag 
        try:
            res = netsnmp.snmpset(var, Version = 2,  DestHost = self.ip, Community=self.password) 
        except (res.ErrorStr, message):
             print("Error: %s" % (message, ))
        #time.sleep(1)
        return res
    
    def getCableDiagAction(self, port):
        # get dlink cable diagnostics start
        # swEtherCableDiagAction.1 .1.3.6.1.4.1.171.12.58.1.1.1.12.1
        base = ".1.3.6.1.4.1.171.12.58.1.1.1.12"
        oid = "%s.%s" % (base, port)
        var = netsnmp.Varbind(oid)
        res = netsnmp.snmpget(var, Version = 2,  DestHost = self.ip, Community=self.password) 
        return res[0]
    
    def getCableDiagPairLenght(self, port):
        # Get dlink cable diagnistic results 
        # should first start diagnostic
        # swEtherCableDiagPair1Lenght .1 .1.3.6.1.4.1.171.12.58.1.1.1.8.1
        # swEtherCableDiagPair2Lenght .1 .1.3.6.1.4.1.171.12.58.1.1.1.9.1
        # swEtherCableDiagPair3Lenght .1 .1.3.6.1.4.1.171.12.58.1.1.1.10.1
        # swEtherCableDiagPair4Lenght .1 .1.3.6.1.4.1.171.12.58.1.1.1.11.1
        PairLenght = []
        PairLenght.append("%s.%s" % (".1.3.6.1.4.1.171.12.58.1.1.1.8", port))
        PairLenght.append("%s.%s" % (".1.3.6.1.4.1.171.12.58.1.1.1.9", port))
        PairLenght.append("%s.%s" % (".1.3.6.1.4.1.171.12.58.1.1.1.10", port))
        PairLenght.append("%s.%s" % (".1.3.6.1.4.1.171.12.58.1.1.1.11", port))
            
        var = netsnmp.VarList()
        for oid in PairLenght:
            var.append(netsnmp.Varbind(oid))

        session = netsnmp.Session(Version = 2, DestHost=self.ip, Community=self.password)
        message = str()
        try:
            res = session.get(var)
        except (session.ErrorStr, message):
            print("Error: %s", (message, ))
        return res
    
    def getCableDiagPairStatus(self, port):
        # swEtherCableDiagPair1Status.1 .1.3.6.1.4.1.171.12.58.1.1.1.4.1
        # swEtherCableDiagPair2Status.1 .1.3.6.1.4.1.171.12.58.1.1.1.5.1
        # swEtherCableDiagPair3Status.1 .1.3.6.1.4.1.171.12.58.1.1.1.6.1
        # swEtherCableDiagPair4Status.1 .1.3.6.1.4.1.171.12.58.1.1.1.7.1
        PairStatusCode = {'0': "ok", '1': "open", '2': "short", '3': "open-short", 
                    '4': "crosstalk", '5':"unknown", '6':"count", '7':"no-cable", '8':"other"}
        
        PairStatus = []
        PairStatus.append("%s.%s" % (".1.3.6.1.4.1.171.12.58.1.1.1.4", port))
        PairStatus.append("%s.%s" % (".1.3.6.1.4.1.171.12.58.1.1.1.5", port))
        PairStatus.append("%s.%s" % (".1.3.6.1.4.1.171.12.58.1.1.1.6", port))
        PairStatus.append("%s.%s" % (".1.3.6.1.4.1.171.12.58.1.1.1.7", port))
        
        var = netsnmp.VarList()
        for oid in PairStatus:
            var.append(netsnmp.Varbind(oid))

        session = netsnmp.Session(Version = 2, DestHost=self.ip, Community=self.password)
        message = str()
        try:
            res = session.get(var)
        except (session.ErrorStr, message):
            print("Error: %s", (message, ))
        new_res = [PairStatusCode[x] for x in res]
        return new_res

    def getCableDiagLinkStatus(self, port):
        #swEtherCableDiagLinkStatus .1.3.6.1.4.1.171.12.58.1.1.1.3
        base = ".1.3.6.1.4.1.171.12.58.1.1.1.3"
        oid = "%s.%s" % (base, port)
        LinkStatus = { '0': "link-down", "1": "link-up", "2": "other"}
        var = netsnmp.Varbind(oid)
        res = netsnmp.snmpget(var, Version = 2, DestHost=self.ip, Community=self.password)
        return LinkStatus[res[0]]

    
    def getCableDiagPortType(self, port):
        # swEtherCableDiagPortType .1.3.6.1.4.1.171.12.58.1.1.1.2
        base = ".1.3.6.1.4.1.171.12.58.1.1.1.2"
        oid = "%s.%s" % (base, port)
        LinkType = {"0":"fastEthernet", "1": "gigaEthernet", "2": "other"}
        var = netsnmp.Varbind(oid)
        res = netsnmp.snmpget(var, Version = 2, DestHost=self.ip, Community=self.password)
        return LinkType[res[0]]
    
    def getCableDiagInfo(self, port):
        dlink.setCableDiagAction(self, port)
        while (dlink.getCableDiagAction == 2):
            pass
        
        CableDiagInfo = {}
        CableDiagInfo['linkstatus'] = dlink.getCableDiagLinkStatus(self, port)
        CableDiagInfo['pairstatus'] = dlink.getCableDiagPairStatus(self, port)
        CableDiagInfo['pairlenght'] = dlink.getCableDiagPairLenght(self, port)
        CableDiagInfo['porttype'] = dlink.getCableDiagPortType(self, port)
        print(CableDiagInfo)
        return CableDiagInfo
        
    def checkHostAlive(self):
        var = netsnmp.Varbind("sysDescr.0")
        res = netsnmp.snmpget(var, Timeout = 100000, Version = 2, DestHost=self.ip, Community=self.password)
        return res
    
        
class zyxel(sw):
    """Defining some zyxel methods"""
    def getPortDescr(self, port):
        base = ".1.3.6.1.4.1.890.1.5.13.6.8.1.1.1"
        oid = "%s.%s" % (base, port)
        var = netsnmp.Varbind(oid)
        res = netsnmp.snmpget(var, Version = 2, DestHost=self.ip, Community=self.password)
        return res[0]
    
    def setPortDescr(self, port, descr):
        base = ".1.3.6.1.4.1.890.1.5.13.6.8.1.1.1"
        #base = ".1.3.6.1.2.1.2.2.1.2"
        oid = "%s.%s" % (base, port)
        var = netsnmp.Varbind(tag = oid, val = descr, type = "OCTETSTR")

        try:
            res = netsnmp.snmpset(var, Version = 2, DestHost=self.ip, Community=self.password)
        except (SNMPError, e):
            print("Error has occured: %s", e)
        
        return res
                 
if __name__ == "__main__":
    #print "key = %s port = %s speed = %s" % (port, ports[port]['port'], ports[port]['speed'])
    print("This is the library it shouldn`t be run directly")
