#!/usr/bin/env python

from autolib.logutils import getLogger
from tests.cue_configs.CueIpv6NdConfig import CueIpv6NdConfig
#from tests.configs.Ipv6NdConfig import Ipv6NdConfig
from nose.plugins.attrib import attr
from tests.lib.base import WithTopo
from autolib.ping import parse as ping_parse
import tests.l2.claglib as claglib
from autolib.sleep import sleep
import json
import operator
import re
import json
import time

log = getLogger('topology')

def deletePerm(dut, name, DeleteAll=True):
    # setting DeleteAll will remove all but the last permanent entry associated with the perm entry specified by name
    # This DeleteAll set to False flag is used to remove all but the last entry. Duplicates are eliminated.
    # There are two files for every specified name
    # This function requires the import of operator

    number_db = {}
    output = dut.device.sudo('ls /var/lib/config-backup/backups/.Descriptions/*-perm')
    list_of_files = output.splitlines()
    for line in list_of_files:
        if name in dut.device.sudo('cat %s' % line):
            fname = line[line.rfind('/')+1:]
            number = dut.device.sudo('cat /var/lib/config-backup/backups/.Numbers/%s' % fname)
            number_db[fname] = number
    if not DeleteAll:
        if len(number_db) > 0:
            exclude = max(number_db.iteritems(), key=operator.itemgetter(1))[0]
            del number_db[exclude]
            exclude = max(number_db.iteritems(), key=operator.itemgetter(1))[0]
            del number_db[exclude]
    if len(number_db) > 0:
        for key in number_db:
            log.info('Removing saved config %s' % key)
            dut.device.sudo('rm /var/lib/config-backup/backups/%s' % key, warn_only=True)
            dut.device.sudo('rm /var/lib/config-backup/backups/.Numbers/%s' % key, warn_only=True)
            dut.device.sudo('rm /var/lib/config-backup/backups/.Descriptions/%s' % key, warn_only=True)
            dut.device.sudo('rm /var/lib/config-backup/backups/.Tags/%s' % key, warn_only=True)


class Ipv6_ND_test(WithTopo):
    timeout = 900000
    '''

Topology:

                              +----------+                           +----------+
                              |          |        L3 Link            |          |
                              |          -----------------------------          |
                              |  R1      |                           |   R2     |
                              |          |        L2 Trunk           |          |
                              |          -----------------------------          |
                              |          |                           |          |
                              +--,-.---.-+,                         _.-,--.--.--+
                                /  |    \  `.,                   _-`  /   |   \
                               /   |    \     ',              _-`    /    |   \
                              /    |     |      `'-----------`       /    |    |
                              /    |      ,      |          |       /     |     ,
                             /     |      |      |          |      /      |     |
                            /      |       \     |          |     /       |      \
                           /       |        ,    | Host55   |     '       |       ,
                          /        |        |    |          |    /        |       |
                         /         |         |   |          |   /         |        |
                        /          |         \   +----------+  /          |        \
                        /          |          \               /           |         \
                       /           |           |              /           |          |
                      /            |           \             /            |          \
                +----/-----+ +-----\----+ +-----'----+ +----/-----+ +-----\----+ +----'-----+
                |          | |          | |          | |          | |          | |          |
                |          | |          | |          | |          | |          | |          |
                |          | |          | |          | |          | |          | |          |
                | Host11   | |Host12    | | Host13   | | Host21   | | Host22   | | Host23   |
                |          | |          | |          | |          | |          | |          |
                |          | |          | |          | |          | |          | |          |
                +----------+ +----------+ +----------+ +----------+ +----------+ +----------+


    R1 and R2 will be using BGP unnumbered to route between them.  There will be two
    links between R1 and R2 one will routed the other will be a L2 trunk.
    The Trunk port will carry vlans 10 and 20. Host11 and
    Host12 will be attached to R1 and R2 L3 ports. Ports attached to Host12 and Host22
    will belong to vlan10 ports attached Host13 and Host23 will belong to vlan 20.
    Ports attached to Host11 and Host21 will configured as L3 interfaces.

    '''
    topo_class = CueIpv6NdConfig
    test_owner = 'gnichols'
    hard_node_guide = {'r1': 'switch'}
    frr_procs = ('zebra', 'bgpd', 'ospfd')
    frr_procs_protocols = ('bgpd', 'ospfd')

    @classmethod
    def post_run_hook(cls):
        r1 = cls.topo.r1
        r2 = cls.topo.r2

        for dut in (r1, r2):
            deletePerm(dut, 'start', DeleteAll=False)
            #dut.device.sudo('net rollback description nclu start')
            dut.device.sudo('systemctl reset-failed frr')
            dut.device.sudo('systemctl restart frr')

    @classmethod
    def post_suite_hook(cls):
        r1 = cls.topo.r1
        r1.device.sudo('net del all')
        r1.device.sudo('net commit verbose')
        deletePerm(r1, 'start')

    def get_interfaces(self, dut, I_faces):
        interfaces = {}
        for intf in I_faces:
            output = dut.device.sudo('net show interface %s' % intf)
            interfaces['%s' % intf] = {}
            interfaces['%s' % intf]['ip_list'] = re.findall('inet6\s+([0-9a-f:/]+)', output)
            interfaces[intf]['local_link'] = ''
            for entry in interfaces[intf]['ip_list']:
                if entry.startswith('fe80:'):
                    address = entry.split('/')
                    interfaces[intf]['local_link'] = address[0]

            initial_values = [['reach_time', '0'], ['retran_intv', '0'], ['advertisements', '0'], ['preference', '0'],
                              ['host_uses', 'null'], ['lifetime', '0'], ['adv_interval', False],
                              ['reachable_time', '0'], ['home_agent', 'False'], ['Home_agent_life_time', '0'],
                              ['Home_agent_preference', '0']]
            for fields in initial_values:
                interfaces['%s' % intf][fields[0]] = fields[1]
            if 'ND advertised reachable time' in output:
                interfaces['%s' % intf]['reach_time'] = str(re.findall('ND advertised reachable time is\s+([0-9]+)\s+milliseconds', output)[0])
            if 'ND advertised retransmit interval' in output:
                interfaces['%s' % intf]['retran_intv'] = str(re.findall('ND advertised retransmit interval is\s+([0-9]+)', output)[0])
            if 'ND router advertisements are sent every' in output:
                interfaces['%s' % intf]['advertisements'] = str(re.findall('ND router advertisements are sent every\s+([0-9]+)', output)[0])
            if 'ND router advertisement default router preference' in output:
                interfaces['%s' % intf]['preference'] = str(re.findall('ND router advertisement default router preference is\s+([a-z]+)', output)[0])
            if 'Hosts use' in output:
                interfaces['%s' % intf]['host_uses'] = str(re.findall('Hosts use\s+([A-Za-z]+)', output)[0])
            if 'advertisements live for' in output:
                interfaces['%s' % intf]['lifetime'] = str(re.findall('ND router advertisements live for\s+([0-9]+)', output)[0])
            if 'Adv. Interval option' in output:
                interfaces['%s' % intf]['adv_interval'] = True
            if 'reachable time is' in output:
                interfaces['%s' % intf]['reachable_time'] =  str(re.findall('reachable time is\s+([0-9]+)', output)[0])
            if 'Home Agent flag' in output:
                interfaces['%s' % intf]['Home_agent'] = True
            if 'Home Agent lifetime is' in output:
                interfaces['%s' % intf]['Home_agent_life_time'] = str(re.findall('Home Agent lifetime is\s+([0-9]+)', output)[0])
            if 'Home Agent preference is' in output:
                interfaces['%s' % intf]['Home_agent_preference'] = str(re.findall('Home Agent preference is\s+([0-9]+)', output)[0])
        return interfaces

    def configuration(self):
        global r1, r2, host11, host12, host13, host21, host22, host23, host55

        r1 = self.topo.r1
        r2 = self.topo.r2

        host11 = self.topo.host11
        host12 = self.topo.host12
        host13 = self.topo.host13
        host21 = self.topo.host21
        host22 = self.topo.host22
        host23 = self.topo.host23
        host55 = self.topo.host55

        r1_ifaces = r1.config.get_swp_interfaces().values()
        r1.swp1 = r1_ifaces[0]
        r1.swp2 = r1_ifaces[1]
        r1.swp3 = r1_ifaces[2]
        r1.swp4 = r1_ifaces[3]
        r1.swp5 = r1_ifaces[4]
        r1.swp6 = r1_ifaces[5]

        r2_ifaces = r2.config.get_swp_interfaces().values()
        r2.swp1 = r2_ifaces[0]
        r2.swp2 = r2_ifaces[1]
        r2.swp3 = r2_ifaces[2]
        r2.swp4 = r2_ifaces[3]
        r2.swp5 = r2_ifaces[4]
        r2.swp6 = r2_ifaces[5]

        host11_ifaces=host11.config.get_swp_interfaces().values()
        host11.swp1 = host11_ifaces[0]

        host12_ifaces=host12.config.get_swp_interfaces().values()
        host12.swp1 = host12_ifaces[0]

        host13_ifaces=host13.config.get_swp_interfaces().values()
        host13.swp1 = host13_ifaces[0]

        host21_ifaces=host21.config.get_swp_interfaces().values()
        host21.swp1 = host21.ifaces[0]

        host22_ifaces=host22.config.get_swp_interfaces().values()
        host22.swp1 = host22_ifaces[0]

        host23_ifaces=host23.config.get_swp_interfaces().values()
        host23.swp1 = host23.ifaces[0]


    def config_host_if(self, host, if_list):
        for interface in if_list:
            host.device.sudo('sysctl -w net/ipv6/conf/%s/forwarding=0' % interface)
            host.device.sudo('sysctl -w net/ipv6/conf/%s/accept_ra=2' % interface)

    @attr(tags=['FR-1063', 'smoke', 'test1'])
    @WithTopo._handle_errors
    def Manage_and_non_managed_test1(self):
        '''
In this test some of the ports will be configured as managed ports and others will
be configured as non managed ports.  The manage ports will try to use dhcp to obtain
ipv6 address/router ip address and the non-manage will use ND to obtain ipv6 address.
Host attached to L3 ports and host attached to access port will be testing in this
test case.

Topology:

  Test will utilize R1, R2, host11,host12, hsot21, host22

Steps:

  - The R1 ports attached to host11 and host12 will be set no ipv6 nd supress-ra.
  - The R2 ports attached to host21 and host22 will be set no ipv6 nd supress-ra, by
    default nd suppression is disabled.
  - Using vtysh configure ipv6 nd managed-config-flag on the port attached to host11
    and host12.
  - Using vtysh configure no ipv6 nd managed-config-flag on the port attached to
    host21 and host22
  - For the ports attached to host11, host12, host21, host22, execute
    net show interface <portname>

Expected_output:
  - Port attached to host11
            Name     MAC                Speed  MTU   Mode
        --  -------  -----------------  -----  ----  ------------
        UP  swp51s1  c4:54:44:f6:50:8d  10G    9216  Interface/L3

        IP Details
        -------------------------  -----------------
        IP:                        2001:cccc:1::1/64
        IP Neighbor(ARP) Entries:  0

        cl-netstat counters
        -------------------
         RX_OK  RX_ERR  RX_DRP  RX_OVR   TX_OK  TX_ERR  TX_DRP  TX_OVR
        ------  ------  ------  ------  ------  ------  ------  ------
        175172       0      23       0  647728       0       0       0

        Routing
        -------
          Interface swp51s1 is up, line protocol is up
          Link ups:       0    last: (never)
          Link downs:     0    last: (never)
          PTM status: disabled
          vrf: Default-IP-Routing-Table
          index 58 metric 0 mtu 9216 speed 10000
          flags: <UP,BROADCAST,RUNNING,MULTICAST>
          Type: Ethernet
          HWaddr: c4:54:44:f6:50:8d
          inet6 fe80::c654:44ff:fef6:508d/64
          inet6 2001:cccc:1::1/64
          Interface Type Other
          ND advertised reachable time is 0 milliseconds
          ND advertised retransmit interval is 0 milliseconds
          ND router advertisements sent: 4445 rcvd: 0
          ND router advertisements are sent every 20 seconds
          ND router advertisements live for 120 seconds
          ND router advertisement default router preference is medium
          Hosts use DHCP to obtain routable addresses.

  - Port attached to host21
            Name     MAC                Speed  MTU   Mode
        --  -------  -----------------  -----  ----  ------------
        UP  swp51s1  c4:54:44:f6:50:8d  10G    9216  Interface/L3

        IP Details
        -------------------------  -----------------
        IP:                        2001:cccc:1::1/64
        IP Neighbor(ARP) Entries:  0

        cl-netstat counters
        -------------------
         RX_OK  RX_ERR  RX_DRP  RX_OVR   TX_OK  TX_ERR  TX_DRP  TX_OVR
        ------  ------  ------  ------  ------  ------  ------  ------
        175172       0      23       0  647724       0       0       0

        Routing
        -------
          Interface swp51s1 is up, line protocol is up
          Link ups:       0    last: (never)
          Link downs:     0    last: (never)
          PTM status: disabled
          vrf: Default-IP-Routing-Table
          index 58 metric 0 mtu 9216 speed 10000
          flags: <UP,BROADCAST,RUNNING,MULTICAST>
          Type: Ethernet
          HWaddr: c4:54:44:f6:50:8d
          inet6 fe80::c654:44ff:fef6:508d/64
          inet6 2001:cccc:1::1/64
          Interface Type Other
          ND advertised reachable time is 0 milliseconds
          ND advertised retransmit interval is 0 milliseconds
          ND router advertisements sent: 4442 rcvd: 0
          ND router advertisements are sent every 20 seconds
          ND router advertisements live for 120 seconds
          ND router advertisement default router preference is medium
          Hosts use stateless autoconfig for addresses.
- Expected_Results: |
    For the port attached to host11, host12 the last line of the output should
    read as follows: Hosts use DHCP to obtain routable addresses.
    For the port attached to host21 and host22 the last line of the output
    should read as follows: Hosts use stateless autoconfig for addresses.

        '''
        self.configuration()
        r1.intf_list = ['%s' % r1.swp3.name, 'vlan10', 'vlan20']
        r2.intf_list = ['%s' % r2.swp3.name, 'vlan10', 'vlan20']
        log.info('Configuring host to accept ND RAs...')
        self.config_host_if(host11, ['%s' % host11.swp1.name])
        self.config_host_if(host12, ['%s' % host12.swp1.name])
        self.config_host_if(host13, ['%s.10' % host13.swp1.name])
        self.config_host_if(host13, ['%s.20' % host13.swp1.name])
        self.config_host_if(host21, ['%s' % host21.swp1.name])
        self.config_host_if(host22, ['%s' % host22.swp1.name])
        self.config_host_if(host23, ['%s' % host23.swp1.name])

        log.info('Setting nd managed-config-flag....')
        r1.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd managed-config-flag"' % r1.swp3.name)
        r1.device.sudo('vtysh -c "config t" -c "interface vlan10" -c "ipv6 nd managed-config-flag"')
        r1.device.sudo('vtysh -c "write"')
        r2.device.sudo('vtysh -c "config t" -c "interface %s" -c "no ipv6 nd managed-config-flag"' % r2.swp3.name)
        r2.device.sudo('vtysh -c "config t" -c "interface vlan10" -c "no ipv6 nd managed-config-flag"')
        r2.device.sudo('vtysh -c "write"')

        log.info('Enabling ND RA....')
        
        for dut in (r1, r2):
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd ra-interval 2"' % dut.swp3.name)
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "no ipv6 nd suppress-ra"' % dut.swp3.name)
            
            for vlan in ('10', '20'):
                dut.device.sudo('vtysh -c "config t" -c "interface vlan%s " -c "ipv6 nd ra-interval 2" '% vlan )
                dut.device.sudo('vtysh -c "config t" -c "interface vlan%s " -c "ipv6 nd prefix 2005:aaaa:%s%s::/64" '% (vlan, vlan, vlan) )
                dut.device.sudo('vtysh -c "config t" -c "interface vlan%s " -c "no ipv6 nd suppress-ra" '% vlan )
                
            dut.device.sudo('write')

        r1.interfaces = self.get_interfaces(r1, r1.intf_list)
        r2.interfaces = self.get_interfaces(r2, r2.intf_list)
        failed = False
        dhcp_list = [[r1, '%s' % r1.swp3.name], [r1, 'vlan10']]
        stateless_list = [[r1, 'vlan20'], [r2, 'vlan20'], [r2, '%s' % r2.swp3.name], [r2, 'vlan10']]

        for dut_int in dhcp_list:
            if dut_int[0].interfaces[dut_int[1]]['host_uses'] != 'DHCP':
                log.info('Failed: %s\'s interface %s was set to Stateless instead of DHCP as expected' % (dut_int[0], dut_int[1]))
                failed = True
        for dut_int in stateless_list:
            if dut_int[0].interfaces[dut_int[1]]['host_uses'] != 'stateless':
                log.info('Failed: %s\'s interface %s was set to DHCP instead of Stateless as expected' % (dut_int[0], dut_int[1]))
                failed = True
        if failed:
            assert False, 'Failed: Some of the interfaces were not set to the proper discovery method.'
        else:
            log.info('Passed: All interfaces were set to the proper discovery methods.')


    @attr(tags=['FR-1063', 'nightly'])
    @WithTopo._handle_errors
    def OtherConfigFlag_test2(self):
        '''
This test case will configure the other-config-flag.  This flag is used, when set, to
tell the host to obtain the additonal configuration form a DHCP server. After the
flag is set tcpdump will be used on the host to determine if the flag has indeed been
set.

Topology:
  Test will utilize R1, R2, host11,host12, hsot21, host22

Steps:
  - The R1 ports attached to host11 and host12 will be set no ipv6 nd supress-ra.
  - The R2 ports attached to host21 and host22 will be set no ipv6 nd supress-ra, by
    default nd suppression is disabled.
  - Using vtysh configure ipv6 nd managed-config-flag on the port attached to host11
    and host12
  - Using vtysh configure no ipv6 nd managed-config-flag on the port attached to
    host21 and host22
  - Using vtysh configure on the ports attached to host11, host12, host21 and host22
    other-config-flag
  - On the host11,host12 host21, and host22 start a tcpdump to capture RA packets
- Expected_Results: |
    On all host the other-config-flag should be set.

        '''
        self.configuration()
        r1.intf_list = ['%s' % r1.swp3.name, 'vlan10', 'vlan20']
        r2.intf_list = ['%s' % r2.swp3.name, 'vlan10', 'vlan20']
        log.info('Configuring host to accept ND RAs...')
        self.config_host_if(host11, ['%s' % host11.swp1.name])
        self.config_host_if(host12, ['%s' % host12.swp1.name])
        self.config_host_if(host13, ['%s.10' % host13.swp1.name])
        self.config_host_if(host13, ['%s.20' % host13.swp1.name])
        self.config_host_if(host21, ['%s' % host21.swp1.name])
        self.config_host_if(host22, ['%s' % host22.swp1.name])
        self.config_host_if(host23, ['%s' % host23.swp1.name])


        log.info('Setting nd managed-config-flag....')
                  
           
            
        for dut in (r1, r2):
            dut.device.sudo('vtysh -c "config t" -c "interface %s " -c "no ipv6 nd suppress-ra"'% dut.swp3.name)
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd ra-interval 2"' % dut.swp3.name)
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10 " -c "no ipv6 nd suppress-ra"')
            dut.device.sudo('vtysh -c "config t" -c "interface vlan20 " -c "no ipv6 nd suppress-ra" ')
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10 " -c "ipv6 nd ra-interval 2" ' )
            dut.device.sudo('vtysh -c "copy running-config startup-config"')
       
        r1.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd managed-config-flag"' % r1.swp3)
        r1.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd other-config-flag"' % r1.swp3)
        r1.device.sudo('vtysh -c "config t" -c "interface vlan10" -c "ipv6 nd managed-config-flag"')
        r1.device.sudo('vtysh -c "write"')
        r2.device.sudo('vtysh -c "config t" -c "interface %s" -c "no ipv6 nd managed-config-flag"' % r2.swp3)
        r2.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd other-config-flag"' % r2.swp3)
        r2.device.sudo('vtysh -c "config t" -c "interface vlan10" -c "no ipv6 nd managed-config-flag"')
        r2.device.sudo('vtysh -c "write"')

        for host in (host11, host12, host21, host22):
            host.device.sudo_bg('timeout 20 tcpdump -vvenni swp1 icmp6 > capture.txt')
        sleep(20)

        failed = False
        for host in (host11, host21):
            output = host.device.sudo('cat capture.txt')
            options = re.findall('Flags\s+([\[\]a-z\s,]+),\s+pref', output)
            if 'other stateful' not in options[0]:
                failed = True
                log.info('The ND other-config-flag was not set for the port attached to %s' % str(host))
                log.info('Packet capture for %s:\n%s' % (host, output))
        if failed:
            assert False, 'Failed: The ND other-config-flag was not set for one or more host.'
        log.info('Passed: All expected host received packets with the ND other-config-flag set.')


    @attr(tags=['FR-1063', 'smoke', 'test3'])
    @WithTopo._handle_errors
    def basic_nd_prefix_test3(self):
        '''

This test will configure a r1 interface attached to host11 and host12 with multiple
prefixes. switchd will be restarted on the host11 and host12 The hosts will be checked
to verify that it has been assigned a ipv6 address for each prefix.

Topology:
  Test will utilize R1, R2, host11,host12, hsot21, host22

Steps:
  - All L3 ports attached to host and all vlans will be set to no ipv6 nd suppress-ra.
  - Using NCLU nd prefixes will be assigned to all L3 ports attached to host and all
    vlans.
  - Using vtysh configure no ipv6 nd managed-config-flag on all L3 ports attached to
    host and all vlans
  - Using vtysh configure on all L3 ports attached to host and all vlans,  no ipv6 nd
    other-config-flag
  - Using NCLU a number of nd prefixes will be assigned to the port of r1 attached to
    all L3 ports attached to host and all vlans
  - From host11 execute the command net show interface swp1
- Expected_Results: |
    All of the prefixes assigned to the r1 port attached to host11 the r1 and r2
    host attached to vlan10 should be found configured on both host11 and the host
    attached to vlan10.
        '''

        self.configuration()
        r1.intf_list = ['%s' % r1.swp3, 'vlan10', 'vlan20']
        r2.intf_list = ['%s' % r2.swp3, 'vlan10', 'vlan20']
        log.info('Configuring host to accept ND RAs...')
        self.config_host_if(host11, ['%s' % host11.swp1.name])
        self.config_host_if(host12, ['%s' % host12.swp1.name])
        self.config_host_if(host13, ['%s.10' % host13.swp1.name])
        self.config_host_if(host13, ['%s.20' % host13.swp1.name])
        self.config_host_if(host21, ['%s' % host21.swp1.name])
        self.config_host_if(host22, ['%s' % host22.swp1.name])
        self.config_host_if(host23, ['%s' % host23.swp1.name])
        
        host11.prefixes = ['2005:abab:aaaa:', '2005:acac:aaaa:', '2005:adad:aaaa:', '2005:afaf:aaaa:']
        host12.prefixes = ['2005:2222:bbbb:', '2005:2223:bbbb:', '2005:2224:bbbb:', '2005:2225:bbbb:']
        
        log.info('Setting nd managed-config-flag....')
       
        for dut in (r1, r2):
            dut.device.sudo('vtysh -c "config t" -c "interface %s " -c "no ipv6 nd suppress-ra"'% dut.swp3.name)
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd ra-interval 2"' % dut.swp3.name)
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10 " -c "no ipv6 nd suppress-ra"')
            dut.device.sudo('vtysh -c "config t" -c "interface vlan20 " -c "no ipv6 nd suppress-ra" ')
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10 " -c "ipv6 nd ra-interval 2" ' )
            dut.device.sudo('vtysh -c "copy running-config startup-config"')

        log.info('Adding prefixes to vlan 10 and to the interface attached to host11...')
       
        for net in host11.prefixes:
            r1.device.sudo('vtysh -c "config t" -c "interface %s " -c "ipv6 nd prefix %s:/64" ' % (r1.swp3.name, net))
           
        for net in host12.prefixes:
            r1.device.sudo('vtysh -c "config t" -c "interface vlan10 " -c "ipv6 nd prefix %s:/64"' % net )
            r1.device.sudo('vtysh -c "copy running-config startup-config"')
           

        sleep(20)
        for dut in (host11, host12):
            output = dut.device.sudo('net show interface json')
            dut.interfaces = json.loads(output)
        failed = False
        for dut in (host11, host12):
            missing = []
            for prefix in dut.prefixes:
                found = False
                if len(dut.interfaces) == 0:
                    assert False, 'There is no interface information for %s' % str(dut)
                for ipaddr in dut.interfaces['swp1']['iface_obj']['ip_address']['allentries']:
                    if prefix in ipaddr:
                        found = True
                if not found:
                    missing.append(prefix)
            if len(missing) > 0:
                log.info('The following prefixes were found on %s interface swp1:\n%s' % (str(dut), dut.interfaces['swp1']['iface_obj']['ip_address']))
                log.info('The following prefixes were missing from %s:\n%s' % (dut, dut.prefixes))
                failed = True
        if failed:
            assert False, 'Failed: Missing prefixes on one or more host'
        log.info('Passed: All prefixes were found on their respective host.')

    @attr(tags=['FR-1063', 'nightly'])
    @WithTopo._handle_errors
    def ra_interval_test4(self):
        '''
In this test the ra-interval will be set to various values on router's interface
attached to one of the host and to vlan10.  To verify that this feature works the
net show interface command will be exected on the router, checking for the ra-interval
value and a packet capture will be executed
on the host and the number of router advertised packets will be counted for a defined
time frame.

Topology:
  Test will utilize R1, R2, host11,host12, hsot21, host22

Steps:
  - All L3 ports attached to host and all vlans will be set to no ipv6 nd suppress-ra.
  - Using NCLU nd prefixes will be assigned to all L3 ports attached to host and all
    vlans
  - Using vtysh configure no ipv6 nd managed-config-flag on all L3 ports attached to
    host and all vlans
  - Using vtysh configure on all L3 ports attached to host and all vlans,  no ipv6 nd
    other-config-flag
  - Using NCLU the ra-interval will be set
  - From the router execute the command net show interface
  - From the host run tcpdump
- Expected_Results: |
    It is expected that the output from the command exectued on the router will
    display the new ra-interval information.  It is also expected that the number of
    packets captured on the host will correspond  to the ra-interval value configured
    on the router.
        '''

        self.configuration()
        r1.intf_list = ['%s' % r1.swp3.name, 'vlan10', 'vlan20']
        r2.intf_list = ['%s' % r2.swp3.name, 'vlan10', 'vlan20']
        log.info('Configuring host to accept ND RAs...')
        self.config_host_if(host11, ['%s' % host11.swp1.name])
        self.config_host_if(host12, ['%s' % host12.swp1.name])
        self.config_host_if(host13, ['%s.10' % host13.swp1.name])
        self.config_host_if(host13, ['%s.20' % host13.swp1.name])
        self.config_host_if(host21, ['%s' % host21.swp1.name])
        self.config_host_if(host22, ['%s' % host22.swp1.name])
        self.config_host_if(host23, ['%s' % host23.swp1.name])

        log.info('Setting nd managed-config-flag and ra-interval to 2....')
        
        for dut in (r1, r2):
            dut.device.sudo('vtysh -c "config t" -c "interface %s " -c "no ipv6 nd suppress-ra"'% dut.swp3.name)
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd ra-interval 2"' % dut.swp3.name)
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10 " -c "no ipv6 nd suppress-ra"')
            dut.device.sudo('vtysh -c "config t" -c "interface vlan20 " -c "no ipv6 nd suppress-ra" ')
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10 " -c "ipv6 nd ra-interval 2" ' )
            dut.device.sudo('vtysh -c "copy running-config startup-config"')
           

        log.info('Starting file capture on host11....')
        result = host11.device.sudo('timeout 20 tcpdump -vvenni swp1 icmp6 > capture.txt', warn_only=True)
        sleep(2)
        output = host11.device.sudo('cat capture.txt')
        nbr_packets = len(re.findall('(router advertisement)', output))
        if nbr_packets < 9 or nbr_packets > 10:
            assert False, 'Failed: Received %d router advertisements but was expecting 10.' % nbr_packets

        log.info('Changing the router advertisement interval to 5...')
        r1.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd ra-interval 5"' % r1.swp3.name)
        r1.device.sudo('vtysh -c "copy running-config startup-config"')
        sleep(10)
        log.info('Starting file capture on host11....')
        result = host11.device.sudo('timeout 20 tcpdump -vvenni swp1 icmp6 > capture.txt', warn_only=True)
        sleep(2)
        output = host11.device.sudo('cat capture.txt')
        nbr_packets = len(re.findall('(router advertisement)', output))
        if nbr_packets < 3 or nbr_packets > 4:
            assert False, 'Failed: Received %d router advertisements but was expecting 4.' % nbr_packets

        log.info('Passed: Router advertisements were generated based on parameters set.')


    @attr(tags=['FR-1063', 'nightly', 'test5'])
    @WithTopo._handle_errors
    def ra_lifetime_test5(self):
        '''

This test case will set the ra-lifetime on the router's interface attached to the host.
The parameter change will be check on the router using the show interface command.  A
packet capture will also be executed on the host to verify that the ra-lifetime is
being advertised properly.

Topology:
  Test will utilize R1, R2, host11,host12, hsot21, host22

Steps:
  - All L3 ports attached to host and all vlans will be set to no ipv6 nd suppress-ra.
  - Using NCLU nd prefixes will be assigned to all L3 ports attached to host and all
    vlans
  - Using vtysh configure no ipv6 nd managed-config-flag on all L3 ports attached to
    host and all vlans
  - Using vtysh configure on all L3 ports attached to host and all vlans,  no ipv6 nd
    other-config-flag
  - Using NCLU the ra-lifetime will be set
  - From the router execute the command net show interface
  - From the host run tcpdump
- Expected_Results: |
    It is expected that the output from the command exectued on the router will
    display the new ra-lifetime information.  It is also expected that ra-lifetime
    valuse will be set properly within the packet.

        '''

        self.configuration()
        r1.intf_list = ['%s' % r1.swp3, 'vlan10', 'vlan20']
        r2.intf_list = ['%s' % r2.swp3, 'vlan10', 'vlan20']
        log.info('Configuring host to accept ND RAs...')
        self.config_host_if(host11, ['%s' % host11.swp1.name])
        self.config_host_if(host12, ['%s' % host12.swp1.name])
        self.config_host_if(host13, ['%s.10' % host13.swp1.name])
        self.config_host_if(host13, ['%s.20' % host13.swp1.name])
        self.config_host_if(host21, ['%s' % host21.swp1.name])
        self.config_host_if(host22, ['%s' % host22.swp1.name])
        self.config_host_if(host23, ['%s' % host23.swp1.name])

        log.info('Setting nd managed-config-flag and ra-interval to 2 and router life_time to 9000....')
        for dut in (r1, r2):
            dut.device.sudo('vtysh -c "config t" -c "interface %s " -c "no ipv6 nd suppress-ra"'% dut.swp3.name)
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd ra-interval 2"' % dut.swp3.name)
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd ra-lifetime 9000"' % dut.swp3.name)
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10 " -c "no ipv6 nd suppress-ra"')
            dut.device.sudo('vtysh -c "config t" -c "interface vlan20 " -c "no ipv6 nd suppress-ra" ')
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10 " -c "ipv6 nd ra-interval 2" ' )
            dut.device.sudo('vtysh -c "copy running-config startup-config"')
 
        log.info('Starting file capture on host11....')
        result = host11.device.sudo('timeout 6 tcpdump -vvenni swp1 icmp6 > capture.txt', warn_only=True)
        sleep(2)
        output = host11.device.sudo('cat capture.txt')
        life_time = re.findall('router lifetime\s+([0-9]+)', output)
        r1.interfaces = self.get_interfaces(r1, ['%s' % r1.swp3.name])
        if life_time[0] == '9000' and r1.interfaces['%s' % r1.swp3.name]['lifetime'] == '9000':
            log.info('ND router life time was set to 9000 as expected.')
        else:
            assert False, 'Failed: ND Router life time was not set to 9000.'
        log.info('Setting ND router life time to 500...')
        r1.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd ra-lifetime 500"' % r1.swp3.name)
        r1.device.sudo('vtysh -c "copy running-config startup-config"')
        sleep(2)
        log.info('Starting file capture on host11....')
        result = host11.device.sudo('timeout 6 tcpdump -vvenni swp1 icmp6 > capture.txt', warn_only=True)
        sleep(2)
        output = host11.device.sudo('cat capture.txt')
        life_time = re.findall('router lifetime\s+([0-9]+)', output)
        r1.interfaces = self.get_interfaces(r1, ['%s' % r1.swp3.name])
        if life_time[0] == '500' and r1.interfaces['%s' % r1.swp3.name]['lifetime'] == '500':
            log.info('ND router life time was set to 500 as expected.')
        else:
            assert False, 'Failed: ND Router life time was not set to 500.'
        log.info('Passed: ND Router life-time is functioning properly.')

    @attr(tags=['FR-1063', 'nightly'])
    @WithTopo._handle_errors
    def adv_interval_option_test6(self):
        '''

This test case will set the adv-interval-option on the router's interface attached
to the host. The parameter change will be check on the router using the show
interface command.  A packet capture will also be executed on the host to verify
that the advertisement interval option is not set.

Topology:
  Test will utilize R1, R2, host11,host12, host21, host22

Steps:
  - All L3 ports attached to host and all vlans will be set to no ipv6 nd suppress-ra.
  - Using NCLU nd prefixes will be assigned to all L3 ports attached to host and all
    vlans
  - Using vtysh configure no ipv6 nd managed-config-flag on all L3 ports attached to
    host and all vlans
  - Using vtysh configure on all L3 ports attached to host and all vlans,  no ipv6 nd
    other-config-flag
  - Using vtysh set the adv-interval-option
  - From the router execute the command net show interface
  - From the host run tcpdump
- Expected_Results: |
    It is expected that the output from the command exectued on the router will
    display the adv-interval-option set.  It is also expected that advertisement
    interval option valuse will be set properly within the packet.

        '''
        self.configuration()
        r1.intf_list = ['%s' % r1.swp3, 'vlan10', 'vlan20']
        r2.intf_list = ['%s' % r2.swp3, 'vlan10', 'vlan20']
        log.info('Configuring host to accept ND RAs...')
        self.config_host_if(host11, ['%s' % host11.swp1.name])
        self.config_host_if(host12, ['%s' % host12.swp1.name])
        self.config_host_if(host13, ['%s.10' % host13.swp1.name])
        self.config_host_if(host13, ['%s.20' % host13.swp1.name])
        self.config_host_if(host21, ['%s' % host21.swp1.name])
        self.config_host_if(host22, ['%s' % host22.swp1.name])
        self.config_host_if(host23, ['%s' % host23.swp1.name])

        log.info('Setting nd managed-config-flag and ra-interval to 2 and router nd adv-interval-option....')
        r1.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd adv-interval-option"' % r1.swp3)
        r1.device.sudo('vtysh -c "write"')

        for dut in (r1, r2):
            dut.device.sudo('vtysh -c "config t" -c "interface %s " -c "no ipv6 nd suppress-ra"'% dut.swp3.name)
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd ra-interval 2"' % dut.swp3.name)
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10 " -c "no ipv6 nd suppress-ra"')
            dut.device.sudo('vtysh -c "config t" -c "interface vlan20 " -c "no ipv6 nd suppress-ra" ')
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10 " -c "ipv6 nd ra-interval 2" ' )
            dut.device.sudo('vtysh -c "copy running-config startup-config"')

        r1.interfaces = self.get_interfaces(r1, ['%s' % r1.swp3])
        if r1.interfaces['%s' % r1.swp3]['adv_interval']:
            log.info('Passed: ND Router adv-interval-option was set as expected')
        else:
            assert False, 'Failed: ND Router adv-interval-option not was set as expected'

    @attr(tags=['FR-1063', 'nightly'])
    @WithTopo._handle_errors
    def nd_reachable_time_test7(self):
        '''

This test case will set the nd reachable-time to a values between 1-3600000 on the
router's interface attached to the host. The parameter change will be check on the
router using the show interface command.  A packet capture will also be executed on
the host to verify that the reachable-time is set to the new value.

Topology:
  Test will utilize R1, R2, host11,host12, host21, host22

Steps:
  - All L3 ports attached to host and all vlans will be set to no ipv6 nd suppress-ra.
  - Using NCLU nd prefixes will be assigned to all L3 ports attached to host and all
    vlans
  - Using vtysh configure no ipv6 nd managed-config-flag on all L3 ports attached to
    host and all vlans
  - Using vtysh configure on all L3 ports attached to host and all vlans,  no ipv6 nd
    other-config-flag
  - Using vtysh set the nd reachable-time to a value
  - From the router execute the command net show interface
  - From the host run tcpdump
- Expected_Results: |
    It is expected that the output from the command exectued on the router will
    display the the new nd reachable-time.  It is also expected that nd ra-interval
    value will be set properly within the packet.

        '''

        self.configuration()
        r1.intf_list = ['%s' % r1.swp3.name, 'vlan10', 'vlan20']
        r2.intf_list = ['%s' % r2.swp3.name, 'vlan10', 'vlan20']
        log.info('Configuring host to accept ND RAs...')
        self.config_host_if(host11, ['%s' % host11.swp1.name])
        self.config_host_if(host12, ['%s' % host12.swp1.name])
        self.config_host_if(host13, ['%s.10' % host13.swp1.name])
        self.config_host_if(host13, ['%s.20' % host13.swp1.name])
        self.config_host_if(host21, ['%s' % host21.swp1.name])
        self.config_host_if(host22, ['%s' % host22.swp1.name])
        self.config_host_if(host23, ['%s' % host23.swp1.name])

        log.info('Setting nd managed-config-flag and ra-interval to 2 and router nd reachable-time to 3600000....')
        r1.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd reachable-time 3600000"' % r1.swp3.name)
        r1.device.sudo('vtysh -c "write"')

        for dut in (r1, r2):
            dut.device.sudo('vtysh -c "config t" -c "interface %s " -c "no ipv6 nd suppress-ra"'% dut.swp3.name)
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd ra-interval 2"' % dut.swp3.name)
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10 " -c "no ipv6 nd suppress-ra"')
            dut.device.sudo('vtysh -c "config t" -c "interface vlan20 " -c "no ipv6 nd suppress-ra" ')
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10 " -c "ipv6 nd ra-interval 2" ' )
            dut.device.sudo('vtysh -c "copy running-config startup-config"')
           
        log.info('Starting file capture on host11....')
        result = host11.device.sudo('timeout 6 tcpdump -vvenni swp1 icmp6 > capture.txt', warn_only=True)
        sleep(2)
        r1.interfaces = self.get_interfaces(r1, ['%s' % r1.swp3.name])

        output = host11.device.sudo('cat capture.txt')
        reachable_time = re.findall('reachable time\s+([0-9]+)', output)
        r1.interfaces = self.get_interfaces(r1, ['%s' % r1.swp3.name])
        if reachable_time[0] == '3600000' and r1.interfaces['%s' % r1.swp3.name]['reachable_time'] == '3600000':
            log.info('ND router reachable-time was set to 3600000 as expected.')
        else:
            assert False, 'Failed: ND Router reachable-time was not set to 36000.'

        log.info('Setting nd router reachable-time to 10000....')
        r1.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd reachable-time 10000"' % r1.swp3.name)
        r1.device.sudo('vtysh -c "write"')

        log.info('Starting file capture on host11....')
        result = host11.device.sudo('timeout 6 tcpdump -vvenni swp1 icmp6 > capture.txt', warn_only=True)
        sleep(2)
        r1.interfaces = self.get_interfaces(r1, ['%s' % r1.swp3.name])

        output = host11.device.sudo('cat capture.txt')
        reachable_time = re.findall('reachable time\s+([0-9]+)', output)
        r1.interfaces = self.get_interfaces(r1, ['%s' % r1.swp3.name])
        if reachable_time[0] == '10000' and r1.interfaces['%s' % r1.swp3.name]['reachable_time'] == '10000':
            log.info('ND router reachable-time was set to 10000 as expected.')
        else:
            assert False, 'Failed: ND Router reachable-time was not set to 10000.'
        log.info('Passed: ND router reachable-time was set and avertised properly')


    @attr(tags=['FR-1063', 'smoke', 'test8'])
    @WithTopo._handle_errors
    def nd_router_preference_test8(self):
        '''

This test case will set the nd router-preference to a values low, medium, or high on
the router's interface attached to the host. The parameter change will be check on the
router using the show interface command.  A packet capture will also be executed on the
host to verify that the router-preference is set to the new value.

Topology:
  Test will utilize R1, R2, host11,host12, host21, host22

Steps:
  - All L3 ports attached to host and all vlans will be set to no ipv6 nd suppress-ra.
  - Using NCLU nd prefixes will be assigned to all L3 ports attached to host and all
    vlans
  - Using vtysh configure no ipv6 nd managed-config-flag on all L3 ports attached to
    host and all vlans
  - Using vtysh configure on all L3 ports attached to host and all vlans,  no ipv6 nd
    other-config-flag
    1) On R1 port swp3 the ND router preference will be set to low.
    2) A packet capture will be started on host11.
    3) The capture packets will be checked to verify that the preference was set to low.
    4) On r1 the interface swp3 will be checked using show interface to verify that the
       preference is set to low.
  - Steps 1 through 4 will be repeated using preference medium and high
    5) On R1 vlan10 the ND router preference will be set to low.
    6) A packet capture will be started on host12.
    7) The capture packets will be checked to verify that the preference was set to low.
    8) On r1 the vlan10 will be checked using show interface to verify that the
       preference is set to low.
  - Steps 5 through 8 will be repeated using preference medium and high

- Expected_Results: |
    It is expected that the output from the net show interface command will
    display the the new router preference.  It is also expected packet capture will
    contain the proper ND router preference
        '''

        def check_preference(dut, host, interface, router_pref):
            log.info('Setting router %s interface %s preference to %s.....' % (str(dut), str(interface), router_pref))
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd router-preference %s"' % (str(interface), router_pref))
            log.info('Starting file capture on %s....' % host)
            result = host.device.sudo('timeout 6 tcpdump -vvenni swp1 icmp6 > capture.txt', warn_only=True)
            sleep(2)
            output = host.device.sudo('cat capture.txt')
            preference = re.findall('hop limit\s+[0-9]+,\s+Flags\s+\[[0-9a-zA-Z]+\],\s+pref\s+([a-z]+),', output)
            dut.interfaces = self.get_interfaces(dut, ['%s' % interface])
            if preference[0] != router_pref or dut.interfaces['%s' % str(interface)]['preference'] != router_pref:
                if dut.interfaces['%s' % str(interface)]['preference'] != router_pref:
                    log.info('%s\'s interface router preference was set %s instead of low.' % (dut, dut.interfaces['%s' % str(interface)]['preference']))
                    log.info('Interface information:\n%s' % r1.device.sudo('net show interface %s' % r1.swp3))
                if preference[0] != router_pref:
                    log.info('The packet capture taken on %s was set to %s instead of low as expected.' % (host, preference[0]))
                    log.info('Packets:\n%s' % output)
                assert False, 'Failed: Router preference was not set to %s as expected.' % router_pref
            log.info('\n %s Router preference was set to %s as expected. %s' % ('*' * 10, router_pref, '*' * 10))

        self.configuration()
        r1.intf_list = ['%s' % r1.swp3, 'vlan10', 'vlan20']
        r2.intf_list = ['%s' % r2.swp3, 'vlan10', 'vlan20']
        log.info('Configuring host to accept ND RAs...')
        self.config_host_if(host11, ['%s' % host11.swp1.name])
        self.config_host_if(host12, ['%s' % host12.swp1.name])
        self.config_host_if(host13, ['%s.10' % host13.swp1.name])
        self.config_host_if(host13, ['%s.20' % host13.swp1.name])
        self.config_host_if(host21, ['%s' % host21.swp1.name])
        self.config_host_if(host22, ['%s' % host22.swp1.name])
        self.config_host_if(host23, ['%s' % host23.swp1.name])

        r1.base = '3333'
        r2.base = '6666'

        for dut in (r1, r2):
            dut.int_db = self.get_interfaces(dut, ['vlan10', 'vlan20', '%s' % dut.swp3.name])
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "no ipv6 nd suppress-ra"' % dut.swp3.name)
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd ra-interval 2"' % dut.swp3.name)
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10 " -c "no ipv6 nd suppress-ra"')
            dut.device.sudo('vtysh -c "config t" -c "interface vlan20 " -c "no ipv6 nd suppress-ra" ')
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10 " -c "ipv6 nd ra-interval 2" ' )
            dut.device.sudo('vtysh -c "config t" -c "interface vlan20 " -c "ipv6 nd ra-interval 2" ' )
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd prefix 200a:%s:4444::/64"' % (dut.swp2.name, dut.base))
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10" -c "ipv6 nd prefix 200a:%s:1010::/64"' %  dut.base)
            dut.device.sudo('vtysh -c "config t" -c "interface vlan20" -c "ipv6 nd prefix 200a:%s:2020::/64"' %  dut.base)
            dut.device.sudo('vtysh -c "copy running-config startup-config"')

        
        sleep(10)
        check_preference(r1, host11, r1.swp3.name, 'low')
        check_preference(r1, host11, r1.swp3.name, 'medium')
        check_preference(r1, host11, r1.swp3.name, 'high')

        check_preference(r1, host12, 'vlan10', 'low')
        check_preference(r1, host12, 'vlan10', 'medium')
        check_preference(r1, host12, 'vlan10', 'high')

        log.info('Passed: All ND router preferences were set as expected.')

    @attr(tags=['FR-1063', 'nightly', 'test9'])
    @WithTopo._handle_errors
    def nd_MTU_test9(self):
        '''

This test case will set the nd MTU to different values for each L3 and vlan attached
to hosts. The parameter change will be check on the router using the show interface
command.  A packet capture will also be executed on the hosts to verify that the new
MTU size is set.

Topology:
  Test will utilize R1, R2, host11,host12, host21, host22

Steps:
  - All L3 ports attached to host and all vlans will be set to no ipv6 nd suppress-ra.
  - Using NCLU nd prefixes will be assigned to all L3 ports attached to host and all
    vlans
  - Using vtysh configure no ipv6 nd managed-config-flag on all L3 ports attached to
    host and all vlans
  - Using vtysh configure on all L3 ports attached to host and all vlans,  no ipv6 nd
    other-config-flag
  - Using vtysh set the nd MTU sized different for each L3 interface and each vlan
    attached to hosts.
  - restart switchd on all host.
  - From the router execute the command net show interface
  - From the hosts run tcpdump
- Expected_Results: |
    It is expected that the output from the command exectued on the router will
    display the the new nd MTU.  It is also expected that the new nd MTU size will be
    captured on each host.

        '''

        self.configuration()
        r1.intf_list = ['%s' % r1.swp3.name, 'vlan10', 'vlan20']
        r2.intf_list = ['%s' % r2.swp3.name, 'vlan10', 'vlan20']
        log.info('Configuring host to accept ND RAs...')
        self.config_host_if(host11, ['%s' % host11.swp1.name])
        self.config_host_if(host12, ['%s' % host12.swp1.name])
        self.config_host_if(host13, ['%s.10' % host13.swp1.name])
        self.config_host_if(host13, ['%s.20' % host13.swp1.name])
        self.config_host_if(host21, ['%s' % host21.swp1.name])
        self.config_host_if(host22, ['%s' % host22.swp1.name])
        self.config_host_if(host23, ['%s' % host23.swp1.name])

        r1.base = '3333'
        r2.base = '6666'

        for dut in (r1, r2):
            dut.int_db = self.get_interfaces(dut, ['vlan10', 'vlan20', '%s' % dut.swp3.name])
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "no ipv6 nd suppress-ra"' % dut.swp3.name)
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd ra-interval 2"' % dut.swp3.name)
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10 " -c "no ipv6 nd suppress-ra"')
            dut.device.sudo('vtysh -c "config t" -c "interface vlan20 " -c "no ipv6 nd suppress-ra" ')
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10 " -c "ipv6 nd ra-interval 2" ' )
            dut.device.sudo('vtysh -c "config t" -c "interface vlan20 " -c "ipv6 nd ra-interval 2" ' )
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd prefix 200a:%s:4444::/64"' % (dut.swp2.name, dut.base))
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10" -c "ipv6 nd prefix 200a:%s:1010::/64"' %  dut.base)
            dut.device.sudo('vtysh -c "config t" -c "interface vlan20" -c "ipv6 nd prefix 200a:%s:2020::/64"' %  dut.base)
            dut.device.sudo('vtysh -c "copy running-config startup-config"')

        log.info('Setting the ND Router mtu on %s and vlan10....' % r1.swp3.name)
        r1.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd mtu 65535"' % r1.swp3.name)
        r1.device.sudo('vtysh -c "config t" -c "interface vlan10" -c "ipv6 nd mtu 10000"')

        log.info('Starting file capture on host11 and host12')
        for host in (host11, host12):
            result = host.device.sudo_bg('timeout 6 tcpdump -vvenni swp1 icmp6 > capture.txt', warn_only=True)
        sleep(8)
        output = host11.device.sudo('cat capture.txt')
        mtu = re.findall('mtu option\s+\([0-9]+\),\s+length\s+[0-9]+\s+\([0-9]+\):\s+([0-9]+)', output)
        if mtu[0] != '65535':
            log.info('Failed: The router advertisement received on host11 had the  ND router mtu was set to %s instead of 65535.' % mtu[0])
        log.info('Passed: The router advertisement received on host11 had ND router mtu 65535 as expected.')
        output = host12.device.sudo('cat capture.txt')
        mtu = re.findall('mtu option\s+\([0-9]+\),\s+length\s+[0-9]+\s+\([0-9]+\):\s+([0-9]+)', output)
        if mtu[0] != '10000':
            log.info('Failed: The router advertisement received on host12 had the ND router mtu was set to %s instead of 10000.' % mtu[0])
        log.info('Passed: The router advertisement received on host12 had ND router mtu 10000 as expected.')

        log.info('Setting the ND Router mtu on %s and vlan10....' % r1.swp3.name)
        r1.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd mtu 1500"' % r1.swp3.name)
        r1.device.sudo('vtysh -c "config t" -c "interface vlan10" -c "ipv6 nd mtu 25000"')

        log.info('Starting file capture on host11 and host12')
        for host in (host11, host12):
            result = host.device.sudo_bg('timeout 6 tcpdump -vvenni swp1 icmp6 > capture.txt', warn_only=True)
        sleep(8)
        output = host11.device.sudo('cat capture.txt')
        mtu = re.findall('mtu option\s+\([0-9]+\),\s+length\s+[0-9]+\s+\([0-9]+\):\s+([0-9]+)', output)
        if mtu[0] != '1500':
            log.info(
                'Failed: The router advertisement received on host11 had the  ND router mtu was set to %s instead of 1500.' %
                mtu[0])
        log.info('Passed: The router advertisement received on host11 had ND router mtu 1500 as expected.')
        output = host12.device.sudo('cat capture.txt')
        mtu = re.findall('mtu option\s+\([0-9]+\),\s+length\s+[0-9]+\s+\([0-9]+\):\s+([0-9]+)', output)
        if mtu[0] != '25000':
            log.info(
                'Failed: The router advertisement received on host12 had the ND router mtu was set to %s instead of 25000.' %
                mtu[0])
        log.info('Passed: The router advertisement received on host12 had ND router mtu 25000 as expected.')

    @attr(tags=['FR-1063', 'nightly', 'test10'])
    @WithTopo._handle_errors
    def nd_home_agent_config_flag_test10(self):
        '''
This test case will set the nd home-agent-config-flag on some L3 interfaces attached to
host and on vlan 10. The parameter change will be check on the router using the show
interface command. A packet capture will also be executed on the hosts to verify that
the flag is set.

Topology:
  Test will utilize R1, R2, host11,host12, host21, host22

Steps:
  - All L3 ports attached to host and all vlans will be set to no ipv6 nd suppress-ra.
  - Using NCLU nd prefixes will be assigned to all L3 ports attached to host and all
    vlans
  - Using vtysh configure no ipv6 nd managed-config-flag on all L3 ports attached to
    host and all vlans
  - Using vtysh configure on all L3 ports attached to host and all vlans,  no ipv6 nd
    other-config-flag
  - Using vtysh set the nd home-agent-config-flag different for some L3 interface and
    vlan10 attached to hosts.
  - restart switchd on all host.
  - From the router execute the command net show interface
  - From the hosts run tcpdump
- Expected_Results: |
    It is expected that the output from the command exectued on the router will display
    the the home-agent-config-flag will be set.  It is also expected that the
    home-agent-config-flag will be captured on hosts where the flag is set on the
    router.

        '''

        self.configuration()
        r1.intf_list = ['%s' % r1.swp3.name, 'vlan10', 'vlan20']
        r2.intf_list = ['%s' % r2.swp3.name, 'vlan10', 'vlan20']
        log.info('Configuring host to accept ND RAs...')
        self.config_host_if(host11, ['%s' % host11.swp1.name])
        self.config_host_if(host12, ['%s' % host12.swp1.name])
        self.config_host_if(host13, ['%s.10' % host13.swp1.name])
        self.config_host_if(host13, ['%s.20' % host13.swp1.name])
        self.config_host_if(host21, ['%s' % host21.swp1.name])
        self.config_host_if(host22, ['%s' % host22.swp1.name])
        self.config_host_if(host23, ['%s' % host23.swp1.name])

        r1.base = '3333'
        r2.base = '6666'
        for dut in (r1, r2):
            dut.int_db = self.get_interfaces(dut, ['vlan10', 'vlan20', '%s' % dut.swp3.name])
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "no ipv6 nd suppress-ra"' % dut.swp3.name)
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd ra-interval 2"' % dut.swp3.name)
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10 " -c "no ipv6 nd suppress-ra"')
            dut.device.sudo('vtysh -c "config t" -c "interface vlan20 " -c "no ipv6 nd suppress-ra" ')
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10 " -c "ipv6 nd ra-interval 2" ' )
            dut.device.sudo('vtysh -c "config t" -c "interface vlan20 " -c "ipv6 nd ra-interval 2" ' )
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd prefix 200a:%s:4444::/64"' % (dut.swp2.name, dut.base))
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10" -c "ipv6 nd prefix 200a:%s:1010::/64"' %  dut.base)
            dut.device.sudo('vtysh -c "config t" -c "interface vlan20" -c "ipv6 nd prefix 200a:%s:2020::/64"' %  dut.base)
            dut.device.sudo('vtysh -c "copy running-config startup-config"')
            sleep(2)
 
        log.info('Setting the ND Router home-agent-config-flag on %s and vlan10....' % r1.swp3.name)
        r1.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd home-agent-config-flag"' % r1.swp3.name)
        r1.device.sudo('vtysh -c "config t" -c "interface vlan10" -c "ipv6 nd home-agent-config-flag"')
        r1.device.sudo('vtysh -c "copy running-config startup-config"')

        sleep(2)
        r1.interfaces = self.get_interfaces(r1, ['%s' % r1.swp3.name, 'vlan10'])
        log.info('Starting file capture on host11 and host12')
        for host in (host11, host12):
            result = host.device.sudo_bg('timeout 6 tcpdump -vvenni swp1 icmp6 > capture.txt', warn_only=True)
            
        sleep(8)
        failed = False
        
        for host, intf in [[host11, '%s' % r1.swp3.name], [host12, 'vlan10']]:
            output = host.device.sudo('cat capture.txt')
            host.flags = re.findall('Flags\s+\[([a-z. ]+)\]', output)
            if 'home agent' not in host.flags[0] or not r1.interfaces['%s' % intf]['Home_agent']:
                failed = True
                if 'home agent' not in host.flags[0]:
                    log.info('The packet being sent to %s did not have the home-agent flag set.' % host)
                if not r1.interfaces['%s' %intf]['Home_agent']:
                    log.info('Show interface on r1\'s interface %s did not have the home-agent flag set.' % intf)
        if failed:
            assert False, 'Failed: The home-agent flag was not advertised to attached host.'
        log.info('Passed:  home-agent flag was advertised for all attached host where the flag was configured.')

    @attr(tags=['FR-1063', 'nightly', 'test11'])
    @WithTopo._handle_errors
    def nd_home_agent_lifetime_test11(self):
        '''

This test case will set the nd home-agent-lifetime <0-65520> on some L3 interfaces
attached tohost and on vlan 10. The parameter change will be check on the router
using the show interface command. A packet capture will also be executed on the hosts
to verify that the flag is set.

Topology:
  Test will utilize R1, R2, host11,host12, host21, host22

Steps:
  - All L3 ports attached to host and all vlans will be set to no ipv6 nd suppress-ra.
  - Using NCLU nd prefixes will be assigned to all L3 ports attached to host and all
    vlans
  - Using vtysh configure no ipv6 nd managed-config-flag on all L3 ports attached to
    host and all vlans
  - Using vtysh configure on all L3 ports attached to host and all vlans,  no ipv6 nd
    other-config-flag
  - Using vtysh set the nd home-agent_lifetime various values, different for some L3
    interface and vlan10 attached to hosts.
  - restart switchd on all host.
  - From the router execute the command net show interface
  - From the hosts run tcpdump
- Expected_Results: |
    It is expected that the output from the command exectued on the router will display
    the the home-agent-lifetime will be set.  It is also expected that the
    home-agent-lifetime will be captured on hosts where the flag is set on the
    router.

        '''

        self.configuration()

        def check_lifetime(life_time):
            log.info('Setting the ND Router home-agent-lifetime on %s  for %s and vlan10 for %s....' % (r1.swp3.name, life_time[0], life_time[1]))
            r1.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd home-agent-lifetime %s"' % (r1.swp3.name, life_time[0]))
            r1.device.sudo('vtysh -c "config t" -c "interface vlan10" -c "ipv6 nd home-agent-lifetime %s"' % life_time[1])
            sleep(2)
            r1.interfaces = self.get_interfaces(r1, ['%s' % r1.swp3.name, 'vlan10'])
            log.info('Starting file capture on host11 and host12')
            for host in (host11, host12):
                result = host.device.sudo_bg('timeout 6 tcpdump -vvenni swp1 icmp6 > capture.txt', warn_only=True)
            sleep(8)
            failed = False
            for host, intf, ltime in [[host11, '%s' % r1.swp3.name, life_time[0]], [host12, 'vlan10', life_time[1]]]:
                output = host.device.sudo('cat capture.txt')
                host.life_time = re.findall('homeagent information option.+lifetime\s+([0-9]+)', output)
                if ltime not in host.life_time[0] or r1.interfaces['%s' % intf]['Home_agent_life_time'] != ltime:
                    failed = True
                    if ltime not in host.life_time[0]:
                        log.info('The packet being sent to %s did not have the home-agent flag set.' % host)
                    if r1.interfaces['%s' % intf]['Home_agent_life_time'] != ltime:
                        log.info('Show interface on r1\'s interface %s did not have the home-agent-lifetime set to %s' % (intf, ltime))
            if failed:
                return False
            else:
                return True

        r1.intf_list = ['%s' % r1.swp3.name, 'vlan10', 'vlan20']
        r2.intf_list = ['%s' % r2.swp3.name, 'vlan10', 'vlan20']
        log.info('Configuring host to accept ND RAs...')
        self.config_host_if(host11, ['%s' % host11.swp1.name])
        self.config_host_if(host12, ['%s' % host12.swp1.name])
        self.config_host_if(host13, ['%s.10' % host13.swp1.name])
        self.config_host_if(host13, ['%s.20' % host13.swp1.name])
        self.config_host_if(host21, ['%s' % host21.swp1.name])
        self.config_host_if(host22, ['%s' % host22.swp1.name])
        self.config_host_if(host23, ['%s' % host23.swp1.name])

        r1.base = '3333'
        r2.base = '6666'
        for dut in (r1, r2):
            dut.int_db = self.get_interfaces(dut, ['vlan10', 'vlan20', '%s' % dut.swp3.name])
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "no ipv6 nd suppress-ra"' % dut.swp3.name)
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd ra-interval 2"' % dut.swp3.name)
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10 " -c "no ipv6 nd suppress-ra" ' )
            dut.device.sudo('vtysh -c "config t" -c "interface vlan20 " -c "no ipv6 nd suppress-ra" ' )
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10 " -c "ipv6 nd ra-interval 2" ' )
            dut.device.sudo('vtysh -c "config t" -c "interface vlan20 " -c "ipv6 nd ra-interval 2" ' )
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd prefix 200a:%s:4444::/64"' % (dut.swp2.name, dut.base))
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10" -c "ipv6 nd prefix 200a:%s:1010::/64"' %  dut.base)
            dut.device.sudo('vtysh -c "config t" -c "interface vlan20" -c "ipv6 nd prefix 200a:%s:2020::/64"' %  dut.base)
            dut.device.sudo('vtysh -c "copy running-config startup-config"')
 
        r1.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd home-agent-config-flag"' % r1.swp3.name)
        r1.device.sudo('vtysh -c "config t" -c "interface vlan10" -c "ipv6 nd home-agent-config-flag"')

        life_time = ['65520', '65520']

        if not check_lifetime(life_time):
            assert False, 'Failed: The home-agent-lifetime was not set to proper value.'

        life_time = ['500', '200']
        if not check_lifetime(life_time):
            assert False, 'Failed: The home-agent-lifetime was not set to proper value.'

        log.info('Passed: home-agent-lifetime values were advertised as configured.')

    @attr(tags=['FR-1063', 'smoke'])
    @WithTopo._handle_errors
    def nd_home_agent_preference_test11(self):
        '''

This test case will set the nd home-agent-preference <0-65535> on some L3 interfaces
attached tohost and on vlan 10. The parameter change will be check on the router
using the show interface command. A packet capture will also be executed on the hosts
to verify that the flag is set.

Topology:
  Test will utilize R1, R2, host11,host12, host21, host22

Steps:
  - All L3 ports attached to host and all vlans will be set to no ipv6 nd suppress-ra.
  - Using NCLU nd prefixes will be assigned to all L3 ports attached to host and all
    vlans
  - Using vtysh configure no ipv6 nd managed-config-flag on all L3 ports attached to
    host and all vlans
  - Using vtysh configure on all L3 ports attached to host and all vlans,  no ipv6 nd
    other-config-flag
  - Using vtysh set the nd home-agent-preference various values, different for some L3
    interface and vlan10 attached to hosts.
  - restart switchd on all host.
  - From the router execute the command net show interface
  - From the hosts run tcpdump
- Expected_Results: |
    It is expected that the output from the command exectued on the router will display
    the the home-agent-preference will be set.  It is also expected that the
    home-agent-lifetime will be captured on hosts where the flag is set on the
    router.

        '''

        self.configuration()

        def check_preference(preference):
            log.info('Setting the ND Router home-agent-preference on %s  for %s and vlan10 for %s....' % (r1.swp3.name,preference[0], preference[1]))
            r1.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd  home-agent-preference %s"' % (r1.swp3.name, preference[0]))
            r1.device.sudo('vtysh -c "config t" -c "interface vlan10" -c "ipv6 nd  home-agent-preference %s"' % preference[1])
            sleep(2)
            r1.interfaces = self.get_interfaces(r1, ['%s' % r1.swp3.name, 'vlan10'])
            log.info('Starting file capture on host11 and host12')
            for host in (host11, host12):
                result = host.device.sudo_bg('timeout 6 tcpdump -vvenni swp1 icmp6 > capture.txt', warn_only=True)
            sleep(8)
            failed = False
            for host, intf, ltime in [[host11, '%s' % r1.swp3.name, preference[0]], [host12, 'vlan10', preference[1]]]:
                output = host.device.sudo('cat capture.txt')
                host.preference = re.findall('homeagent information option.+preference\s+([0-9]+)', output)
                if ltime not in host.preference[0] or r1.interfaces['%s' % intf]['Home_agent_preference'] != ltime:
                    failed = True
                    if ltime not in host.preference[0]:
                        log.info('The packet being sent to %s did not have the home-agent preference set to the proper value.' % host)
                    if r1.interfaces['%s' % intf]['Home_agent_preference'] != ltime:
                        log.info(
                            'Show interface on r1\'s interface %s did not have the home-agent-preference set to %s' % (
                            intf, ltime))
            if failed:
                return False
            else:
                return True

        r1.intf_list = ['%s' % r1.swp3.name, 'vlan10', 'vlan20']
        r2.intf_list = ['%s' % r2.swp3.name, 'vlan10', 'vlan20']
        log.info('Configuring host to accept ND RAs...')
        self.config_host_if(host11, ['%s' % host11.swp1.name])
        self.config_host_if(host12, ['%s' % host12.swp1.name])
        self.config_host_if(host13, ['%s.10' % host13.swp1.name])
        self.config_host_if(host13, ['%s.20' % host13.swp1.name])
        self.config_host_if(host21, ['%s' % host21.swp1.name])
        self.config_host_if(host22, ['%s' % host22.swp1.name])
        self.config_host_if(host23, ['%s' % host23.swp1.name])
        r1.base = '3333'
        r2.base = '6666'
        for dut in (r1, r2):
            dut.int_db = self.get_interfaces(dut, ['vlan10', 'vlan20', '%s' % dut.swp3.name])
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "no ipv6 nd suppress-ra"' % dut.swp3.name)
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd ra-interval 2"' % dut.swp3.name)
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10 " -c "no ipv6 nd suppress-ra" ' )
            dut.device.sudo('vtysh -c "config t" -c "interface vlan20 " -c "no ipv6 nd suppress-ra" ' )
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10 " -c "ipv6 nd ra-interval 2" ' )
            dut.device.sudo('vtysh -c "config t" -c "interface vlan20 " -c "ipv6 nd ra-interval 2" ' )
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd prefix 200a:%s:4444::/64"' % (dut.swp2.name, dut.base))
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10" -c "ipv6 nd prefix 200a:%s:1010::/64"' %  dut.base)
            dut.device.sudo('vtysh -c "config t" -c "interface vlan20" -c "ipv6 nd prefix 200a:%s:2020::/64"' %  dut.base)
            dut.device.sudo('vtysh -c "copy running-config startup-config"')
 
        r1.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd home-agent-config-flag"' % r1.swp3.name)
        r1.device.sudo('vtysh -c "config t" -c "interface vlan10" -c "ipv6 nd home-agent-config-flag"')

        preference = ['65520', '65520']
        if not check_preference(preference):
            assert False, 'Failed: The home-agent-preference was not set to proper value.'

        preference = ['30', '1']
        if not check_preference(preference):
            assert False, 'Failed: The home-agent-preference was not set to proper value.'
        log.info('Passed: home-agent-preference values were advertised as configured.')

    @attr(tags=['FR-1063', 'nightly'])
    @WithTopo._handle_errors
    def nd_home_RA_on_interface_test12(self):
        '''

This test case will verify that router advertisements are advertised across L3 ports,
L2 access ports, and L2 trunk ports.

Topology:
  Test will utilize R1, R2, host11,host12, host13

Steps:
  - All L3 ports attached to host and all vlans will be set to no ipv6 nd suppress-ra.
  - Using NCLU nd prefixes will be assigned to all L3 ports attached to host and all
    vlans
  - Using vtysh configure no ipv6 nd managed-config-flag on all L3 ports attached to
    host and all vlans
  - Using vtysh configure on all L3 ports attached to host and all vlans,  no ipv6 nd
    other-config-flag
  - Using vtysh set the nd home-agent-preference various values, different for some L3
    interface and vlan10 attached to hosts.
  - restart switchd on all host.
  - From the router execute the command net show interface
  - From the hosts run tcpdump
- Expected_Results: |
    It is expected that router advertisements will be capture on Host L3 ports,
    host L2 access ports, and host trunk ports.
        '''

        self.configuration()

        r1.intf_list = ['%s' % r1.swp3, 'vlan10', 'vlan20']
        r2.intf_list = ['%s' % r2.swp3, 'vlan10', 'vlan20']
        log.info('Configuring host to accept ND RAs...')
        self.config_host_if(host11, ['%s' % host11.swp1.name])
        self.config_host_if(host12, ['%s' % host12.swp1.name])
        self.config_host_if(host13, ['%s.10' % host13.swp1.name])
        self.config_host_if(host13, ['%s.20' % host13.swp1.name])
        self.config_host_if(host21, ['%s' % host21.swp1.name])
        self.config_host_if(host22, ['%s' % host22.swp1.name])
        self.config_host_if(host23, ['%s' % host23.swp1.name])
        r1.base = '3333'
        r2.base = '6666'
        for dut in (r1, r2):
            dut.int_db = self.get_interfaces(dut, ['vlan10', 'vlan20', '%s' % dut.swp3.name])
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "no ipv6 nd suppress-ra"' % dut.swp3.name)
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd ra-interval 2"' % dut.swp3.name)
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10 " -c "no ipv6 nd suppress-ra" ' )
            dut.device.sudo('vtysh -c "config t" -c "interface vlan20 " -c "no ipv6 nd suppress-ra" ' )
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10 " -c "ipv6 nd ra-interval 2" ' )
            dut.device.sudo('vtysh -c "config t" -c "interface vlan20 " -c "ipv6 nd ra-interval 2" ' )
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd prefix 200a:%s:4444::/64"' % (dut.swp2.name, dut.base))
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10" -c "ipv6 nd prefix 200a:%s:1010::/64"' %  dut.base)
            dut.device.sudo('vtysh -c "config t" -c "interface vlan20" -c "ipv6 nd prefix 200a:%s:2020::/64"' %  dut.base)
            dut.device.sudo('vtysh -c "copy running-config startup-config"')
 
        sleep(2)
        host_list = [[host11, '%s' % host11.swp1.name, 'capture.txt'], [host12, '%s' % host12.swp1.name, 'capture.txt'],
                     [host13, '%s.10' % host13.swp1.name, 'capture10.txt'], [host13, '%s.20' % host13.swp1.name, 'capture20.txt']]
        for host, intf, filename in host_list:
            result = host.device.sudo_bg('timeout 10 tcpdump -vvenni %s icmp6 > %s' % (intf, filename))
        sleep(12)
        passed = True
        for host, intf, filename in host_list:
            output = host.device.sudo('cat %s' % filename)
            packet_count = len(re.findall('(router advertisement)', output))
            if packet_count == 0:
                passed = False
                log.info('Failed: No router advertisements were seen on %s for interface %s' % (host, intf))
        if not passed:
            log.info('\nhost11 is connect to r1 with a L3 port,\nhost12 is attached to r1 with an access port,\nhost13 is attached to r1 with a trunk port.')
            assert False, 'Failed: not all host recieved router advertisements.'
        log.info('Passed: All host receieved rotuer advertisements.')

    @attr(tags=['FR-1063', 'smoke', 'current', 'prefix', 'checking'])
    @WithTopo._handle_errors
    def nd_home_RA_on_clag_test13(self):
        '''

This test case will verify that router advertisements are advertised across L3 ports,
L2 access ports, L2 trunk ports and mlag ports. Verify that default routes are set
for the same.

Topology:
  Test will utilize R1, R2, host11,host12, host13, host55

Steps:
  - All L3 ports attached to host and all vlans will be set to no ipv6 nd suppress-ra.
  - Using NCLU nd prefixes will be assigned to all L3 ports attached to host and all
    vlans
  - Using vtysh configure no ipv6 nd managed-config-flag on all L3 ports attached to
    host and all vlans
  - Using vtysh configure on all L3 ports attached to host and all vlans,  no ipv6 nd
    other-config-flag
  - Using vtysh set the nd home-agent-preference various values, different for some L3
    interface and vlan10 attached to hosts.
  - restart switchd on all host.
  - From the router execute the command net show interface
  - From the hosts run tcpdump
- Expected_Results: |
    It is expected that router advertisements will be capture on Host L3 ports,
    host L2 access ports, and host trunk ports. It is also expected that the
    host will have their default routes will be configured correctly.
        '''

        self.configuration()


        r1.hostid = ['1', '2']
        r2.hostid = ['2', '1']
        sleep(5)
        for dut in (r1, r2):
            dut.device.sudo('net add bond peerlink bond slaves %s' % dut.swp1)
            dut.device.sudo('net add interface peerlink.4094 ipv6 address 2009:aaaa:bbbb::%s/64' % dut.hostid[0])
            dut.device.sudo('net add interface peerlink.4094 clag peer-ip 2009:aaaa:bbbb::%s' % dut.hostid[1])
            dut.device.sudo('net add interface peerlink.4094 clag backup-ip 192.168.0.1')
            dut.device.sudo('net add interface peerlink.4094 clag sys-mac 44:38:39:FF:40:94')
            dut.device.sudo('net add bond channel_1 bond slaves %s' % dut.swp6)
            dut.device.sudo('net add bond channel_1 clag id 1')
            dut.device.sudo('net add bond channel_1 bridge access 55')
            dut.device.sudo('net commit verbose')

        host55.device.sudo('net add bond channel_1 bond slaves swp1,swp2')
        host55.device.sudo('net commit')

        r1.intf_list = ['%s' % r1.swp3.name, 'vlan10', 'vlan20']
        r2.intf_list = ['%s' % r2.swp3.name, 'vlan10', 'vlan20']
        log.info('Configuring host to accept ND RAs...')
        self.config_host_if(host11, ['%s' % host11.swp1.name])
        self.config_host_if(host12, ['%s' % host12.swp1.name])
        self.config_host_if(host13, ['%s.10' % host13.swp1.name])
        self.config_host_if(host13, ['%s.20' % host13.swp1.name])
        self.config_host_if(host21, ['%s' % host21.swp1.name])
        self.config_host_if(host22, ['%s' % host22.swp1.name])
        self.config_host_if(host23, ['%s' % host23.swp1.name])
        self.config_host_if(host55, ['channel_1'])

        r1.base = '3333'
        r2.base = '6666'

        r1.device.sudo('vtysh -c "config t" -c "interface vlan55" -c "ipv6 nd router-preference high"')
        for dut in (r1, r2):
            dut.int_db = self.get_interfaces(dut, ['vlan10', 'vlan20', '%s' % dut.swp3.name])
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "no ipv6 nd suppress-ra"' % dut.swp3.name)
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd ra-interval 2"' % dut.swp3.name)
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10 " -c "no ipv6 nd suppress-ra" ' )
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10 " -c "no ipv6 nd suppress-ra" ' )
            dut.device.sudo('vtysh -c "config t" -c "interface vlan20 " -c "no ipv6 nd suppress-ra" ' )
            dut.device.sudo('vtysh -c "config t" -c "interface vlan20 " -c "no ipv6 nd suppress-ra" ' )
            dut.device.sudo('vtysh -c "config t" -c "interface vlan55 " -c "no ipv6 nd suppress-ra" ' )
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10 " -c "ipv6 nd ra-interval 2" ' )
            dut.device.sudo('vtysh -c "config t" -c "interface vlan20 " -c "ipv6 nd ra-interval 2" ' )
            dut.device.sudo('vtysh -c "config t" -c "interface vlan55 " -c "ipv6 nd ra-interval 2" ' )
            dut.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd prefix 200a:%s:4444::/64"' % (dut.swp2.name, dut.base))
            dut.device.sudo('vtysh -c "config t" -c "interface vlan10" -c "ipv6 nd prefix 200a:%s:1010::/64"' %  dut.base)
            dut.device.sudo('vtysh -c "config t" -c "interface vlan20" -c "ipv6 nd prefix 200a:%s:2020::/64"' %  dut.base)
            dut.device.sudo('vtysh -c "config t" -c "interface vlan55" -c "ipv6 nd prefix 2001:dada:dada::/64"')
            dut.device.sudo('vtysh -c "copy running-config startup-config"')
        sleep(2)
        found = False
        count = 0
        seconds = 190
        log.info('Waiting for clag channel_1 to go online..........')
        while not found:
            output = r1.device.sudo('net show interface channel_1 json')
            ch_db = json.loads(output)
            if ch_db['linkstate'] == 'UP':
                found = True
            else:
                log.debug('clag channel_1 is %s. %d seconds have elapsed.' % (str(ch_db['linkstate']), count))
            assert count < seconds, 'Failed: clag channel_1 did not come up within %d seconds.' % seconds
            count += 1
            sleep(1)
        log.info('It took %d seconds for the clag channel_1 to come up.' % count)
        log.info('Starting packet capture on host 11, 13 and 55......')
        host_list = [[host11, '%s' % host11.swp1.name, 'capture.txt'], [host12, '%s' % host12.swp1.name, 'capture.txt'],
                     [host13, '%s.10' % host13.swp1.name, 'capture10.txt'], [host13, '%s.20' % host13.swp1.name, 'capture20.txt'],
                     [host55, 'channel_1', 'bond.txt']]
        for host, intf, filename in host_list:
            result = host.device.sudo_bg('timeout 120 tcpdump -vvenni %s icmp6 > %s' % (intf, filename))
        log.info('Sleeping for 122 seconds for completion of packet capture.')
        sleep(122)
        passed = True
        for host, intf, filename in host_list:
            output = host.device.sudo('cat %s' % filename)
            packet_count = len(re.findall('(router advertisement)', output))
            if packet_count == 0:
                passed = False
                log.info('Failed: No router advertisements were seen on %s for interface %s' % (host, intf))
        if not passed:
            log.info('\nhost11 is connect to r1 with a L3 port,\nhost12 is attached to r1 with an access port,\nhost13 is attached to r1 with a trunk port.')
            assert False, 'Failed: not all host recieved router advertisements.'
        log.info('Passed: All host received router advertisements.')

        r1.interface_list = ['%s' % r1.swp3.name, 'vlan10', 'vlan20', 'vlan55']
        r2.interface_list = ['%s' % r2.swp3.name, 'vlan10', 'vlan20', 'vlan55']
        r1.interfaces = self.get_interfaces(r1, r1.interface_list)
        r2.interfaces = self.get_interfaces(r2, r2.interface_list)

        log.info('Checking default routes on all host.....')

        failed = False
        output = host11.device.sudo('net show route')
        default_route = re.findall('K>\*\s+(::/0)\s+\[[0-9/]+\]\s+via\s+([0-9a-f:]+),\s+([a-z0-9A-Z_\.]+)', output)
        if default_route[0][1] == r1.interfaces['%s' % r1.swp3.name]['local_link']:
            log.info('Default route was set properly for host11')
        else:
            log.info('Failed: Default route was not set properly for host11')
            log.info('Default route: %s and %s' % (default_route[0][1], r1.interfaces['%s' % r1.swp3.name]['local_link']))
            log.info('Route information for host11:\n%s' % host11.device.sudo('net show route'))
            failed = True
        output = host12.device.sudo('net show route')
        default_route = re.findall('K>\*\s+(::/0)\s+\[[0-9/]+\]\s+via\s+([0-9a-f:]+),\s+([a-z0-9A-Z_\.]+)', output)
        if default_route[0][1] == r1.interfaces['vlan10']['local_link'] or default_route[0][1] == r2.interfaces['vlan10']['local_link']:
            log.info('Default route was set properly for host12')
        else:
            log.info('Failed: Default route was not set properly for host12')
            log.info('Default route: %s r1 vlan10 %s and r2 vlan10 %s' % (default_route[0][1], r1.interfaces['vlan10']['local_link'], r2.interfaces['vlan10']['local_link']))
            log.info('Route information for host12:\n%s' % host11.device.sudo('net show route'))
            failed = True
        output = host55.device.sudo('net show route')
        default_route = re.findall('K>\*\s+(::/0)\s+\[[0-9/]+\]\s+via\s+([0-9a-f:]+),\s+([a-z0-9A-Z_\.]+)', output)
        if default_route[0][1] == r1.interfaces['vlan55']['local_link'] or default_route[0][1] == r2.interfaces['vlan55']['local_link']:
            log.info('Default route was set properly for host55')
        else:
            log.info('Failed: Default route was not set properly for host55')
            log.info('Default route: %s r1 vlan55 %s and r2 vlan10 %s' % (default_route[0][1], r1.interfaces['vlan55']['local_link'], r2.interfaces['vlan55']['local_link']))
            log.info('Route information for host55:\n%s' % host11.device.sudo('net show route'))
            failed = True

        if failed:
            assert False, 'Failed:  Default route was not set on one or more host.'
        log.info('Passed: All router advertisements were seen on all host and defaullt routes were set on all host as well.')

        log.info('Setting nd prefix flags.')
        result = host11.device.sudo_bg('timeout 10 tcpdump -vvenni %s icmp6 > %s' % (host11.swp1.name, 'capture.txt'))
        r1.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd prefix 2001:dada:dada::/64 no-autoconfig"' % r1.swp3.name)
        r1.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd prefix 2001:2020:5050::/64 router-address"' % r1.swp3.name)
        r1.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd prefix 2001:1111:2222::/64 off-link"' % r1.swp3)
        r1.device.sudo('vtysh -c "config t" -c "interface %s" -c "ipv6 nd prefix 2001:1010:4040::/64 infinite 500"' % r1.swp3)
        r1.device.sudo ('vtysh -c "config t" -c "interface %s" -c "ipv6 nd prefix 2002:3333:4444::/64 off-link no-autoconfig"' % r1.swp3)

        sleep(11)
        output = host11.device.sudo('cat capture.txt')
        ra_list = output.split('router advertisement')
        last_ra = str(ra_list[len(ra_list) - 1])
        prefix_list = re.findall(
            'prefix info option\s+[\(\)0-9]+,\s+length\s+[0-9]+\s+[\(\)0-9]+:\s+([0-9a-f:\/]+),\s+Flags\s+\[([a-z,\s]+)\],\s+valid time\s+([0-9a-z]+),\s+pref\.\s+time\s([0-9a-z]+)',
            last_ra)
        failed = False
        for prefix in prefix_list:
            if str(prefix[0]) == '2001:dada:dada::/64':

                if 'auto' not in prefix[1]:
                    log.info('Passed no-autoconfig flag was set correctly')
                else:
                    log.info('Failed: no-autoconfig flag was not set correctly')
                    failed = True
            if str(prefix[0]) == '2001:2020:5050::/64':
                if 'router' in prefix[1]:
                    log.info('Passed: The router-address flag was set as expected')
                else:
                    log.info('Failed: The router-address flag was not set as expected')
                    failed = True
            if str(prefix[0]) == '2001:1111:2222::/64':
                if 'onlink' not in prefix[1]:
                    log.info('Passed: The onlink flag was not set as expected')
                else:
                    log.info('Failed: The onlink flag was set unexpectedly')
                    failed = True
            if str(prefix[0]) == '2001:1010:4040::/64':
                if 'infinity' in prefix[2] and '500' in prefix[3]:
                    log.info('Passed: Valid time was set to infinty as expected, and preferred time was set to 500.')
                else:
                    log.info('Failed: Either the Valid time was not set to infinity or the preferred time was not set to 500')
                    failed = True
            if str(prefix[0]) == '2002:3333:4444::/64':
                if 'none' in prefix[1]:
                    log.info('Passed: The off-link and no-autoconfig flags were set correclty.')
                else:
                    log.info(
                        'Failed: Either the off-link or the no-autoconfig flags were not set correctly')
                    failed = True
        if failed:
            assert False, 'Failed:  Some or all of the nd prefix flags could not be set correctly.'
        log.info('Passed: All nd prefix flags were set correctly.')



