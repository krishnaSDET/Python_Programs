#!/usr/bin/env python
# Copyright 2015 Cumulus Networks, LLC
#
# configuration for for 8 port switch
#

from autolib.logutils import getLogger
from ipaddress import IPv4Network, IPv6Network, IPv4Address, IPv4Interface
from tests.specs.ClagVRRSpec import ClagVRRSpec
from tests.specs.ClagVRRSpec import ClagVRRDualLinkBondSpec
from ssim2.Topology import Topology
import os
import tests.lib.general.general_defs as genDefs
from autolib.sleep import sleep
import ssim2.net as net
# CUE
from cafe.cue_config import *
import pprint
log = getLogger('topology')

############################

class ClagVrrNewBridgeDriverConfig(ClagVRRSpec, Topology):

    def __init__(self):
        ClagVRRSpec.__init__(self)
        Topology.__init__(self)

        for nvue_node in list(self.G.keys()):
            nvue_node.config_enabled = True
        

    def configure_topo(self):
        '''
        Configure the network for the VMware MLAG setup. This script configures all
        hosts so that the swp1 and swp2 ports are bonded, and have VLAN subinterfaces
        with IP addresses. The switches are configured with single-port bonds on
        the downlinks and uplinks, with VLAN subinterfaces, and are members of
        a bridge. The ISL links are two-port bonds, each with VLAN subinterfaces and
        are also members of the bridges. Additionally, a management VLAN subinterface
        exists on the ISL link which is not part of any bridge but is assigned an
        IP address.

        :Parameters:
            - `spec`: The network spec which contains, most importantly, a list of
                    nodes.

        :Return:
            Nothing - But will write out config files prior to exit

        :Exceptions:
            None. If an serious error is encountered, we exit()
        '''

        _NUM_VLANS = 5
        _VLAN_BASE = 100
        _MGMT_VLAN = 4000
        _NATIVE_VLAN = 1
        vlanRange = "%d-%d" % (_VLAN_BASE, _VLAN_BASE + _NUM_VLANS)
        vlan_list = range(_VLAN_BASE, _VLAN_BASE + _NUM_VLANS)

        for node in self.nodes():
            node.config.render_method = RENDER_CUE_YAML

        def configure_bond(node, index, role, addrs, ifaces, area, mode, name_prefix="bond", clagId=None):
            for iface in ifaces:
                bond = node.config.add_bond_interface(
                    name=name_prefix+str(index))
                bond.bond.members.append(iface)
                bond.bond.role = role
            if isinstance(mode, str) and ((mode.lower() == "lacp") or (mode == "802.3ad")):
                log.info('Default bond mode is 802.3ad so not configuring it')
            else:
                bond.bond.mode = "balance-xor"
            if clagId != None:
                bond.bond.mlag.id = clagId
            return bond

        def configure_bridge(node, role, addrs, ifaces, area, VA='False'):
            '''
            Create a bridge.

            :Parameters:
                - `node`: The node in which the bridge will be created
                - `role`: The role of this interface, can be any string
                - `addrs`: A list of IP addresses to assign to this interface
                - `ifaces`: A list of interfaces which are bridge members
                - `area`: The routing area for this bridge
                - 'VA': VLAN aware are not.

            :Returns:
                The bridge interface which was created
            '''
            bridge_obj = node.config.add_bridge("br_default")
            bridge_obj.role = role
            bridge_obj.type = "vlan-aware"
            for intf in ifaces:
                if intf.name != "peerlink":
                    swp_br = intf.add_bridges("br_default")
                    print(dir(swp_br))
                    print(dir(swp_br.vlan))
                    swp_br.vlan = vlan_list
                    if VA:
                        swp_br.stp.admin_edge = "on"
            if not VA:
                bridge_obj.ip.address = address
            return bridge_obj

        def configure_vlan(node, bridge_obj, vlan, ip_list, role=''):
            """
            This function is to configure the svi interface
            """
            vlan_temp = bridge_obj.add_vlan(str(vlan))
            sub_int = node.config.add_sub_interface(
                bridge_obj, vlan_id=vlan, name='vlan'+str(vlan))
            sub_int.role = role
            for ip in ip_list:
                sub_int.ip.address.append(ip)
            return sub_int

        def configure_vrr(node, svi_intf, vrr_mac, ip_list):
            """
            This function is to configure the vrr interface ip
            """
            vrr_obj = svi_intf.ip.vrr
            vrr_obj.mac_address = vrr_mac
            for ip in ip_list:
                vrr_obj.address.append(ip)

        def configure_sub_interface(node, vlan_id, role, address, iface):
            if 'br_default' in iface.name:
                br = node.config.get_bridge_interfaces()
                br.values()[0].vlan = vlan_id
            else:
                iface.vlan = vlan_id

            sub_int = node.config.add_sub_interface(
                iface, vlan_id=vlan_id, name=iface.name+"."+str(vlan_id))
            sub_int.role = role
            if address:
                sub_int.ip.address = address
            return sub_int

        def get_neighbors(iface):
            '''
            Returns an unordered set of neighbor nodes for the given interface.
            '''
            if isinstance(iface, CueSwp):
                return {iface.opposite.node}
            elif isinstance(iface, CueBridge):
                neighbors = set()
                for bintf in iface.ifaces:
                    neighbors |= get_neighbors(bintf)
                return neighbors
            elif isinstance(iface, CueBond):
                return get_neighbors(iface.bond.members[0])
            elif isinstance(iface, CueSubInterface):
                return get_neighbors(iface.parent_intf)
            else:
                log.info(
                    "Error: Unknown interface class for interface: %s" % (iface.name))
                sys.exit(1)

        def add_mlag_config(router_ips):
            # Now add the IP addresses to the management VLANs of the switches
            firstSwitches = []
            for node in self.nodes():
                if node.role == "ChardSwitch":
                    if node.subrole == "vrr1":
                        firstSwitches = [node]
                    clagIdx = 1
                    node_bond_ifaces = node.config.get_bond_interfaces().values()

                    for iface in node_bond_ifaces:
                        if iface.name != 'peerlink':
                            iface.bond.mlag.id = clagIdx
                            clagIdx += 1
                    mlag_obj = node.config.add_mlag()
                    mlag_obj.mac_address = "00:00:00:aa:bb:01"
                    mlag_obj.init_delay = 10
                    if node.name == 'p1c1s1':
                        mlag_obj.add_backup(router_ips[2])
                    elif node.name == 'p1c1s2':
                        mlag_obj.add_backup(router_ips[1])

            for node in firstSwitches:

                mgmtVlans = [i for i in node.config.get_mlag_peerlink_interfaces(
                ).values() if i.role == "MgmtVlan"]
                for iface in mgmtVlans:
                    mgmtsubnet = next(ipsubnets)
                    mgmthosts = mgmtsubnet.hosts()
                    addr = "%s/%s" % (next(mgmthosts), mgmtsubnet.prefixlen)
                    addr2 = "%s/%s" % (next(mgmthosts), mgmtsubnet.prefixlen)
                    peer_link_obj = node.config.get_mlag_peerlink_interfaces().values()[
                        0]
                    peer_sub_obj = node.config.add_mlag_sub_peerlink(
                        peer_link_obj, 4094)
                    peer_sub_obj.ip.address.append(IPv4Interface(addr))
                    neighbors = get_neighbors(iface)
                    if len(neighbors) != 1:
                        log.info(
                            "The interface %s should only have a single neighbor. It has %d: %s" %
                            (iface.name, len(neighbors), neighbors))
                        sys.exit(1)
                    neighbor = neighbors.pop()
                    neighMgmtVlans = [i for i in neighbor.config.get_mlag_peerlink_interfaces(
                    ).values() if i.role == "MgmtVlan"]
                    for niface in neighMgmtVlans:
                        peer_link_obj = neighbor.config.get_mlag_peerlink_interfaces().values()[
                            0]
                        peer_sub_nobj = neighbor.config.add_mlag_sub_peerlink(
                            peer_link_obj, 4094)

                        peer_sub_nobj.ip.address.append(IPv4Interface(addr2))
                    node.config.mlag.peer_ip = IPv4Interface(
                        IPv4Interface(addr2).ip)
                    neighbor.config.mlag.peer_ip = IPv4Interface(
                        IPv4Interface(addr).ip)
                clagArgs = ['--redirect2Enable False --debug 0xFFFFFFFF']
                if not node.hard_target:
                    clagArgs.append('--vm')
                if len(clagArgs):
                    peer_sub_obj.eni_snippet.append(
                        "clagd-args %s" % (" ".join(clagArgs)))
                    peer_sub_nobj.eni_snippet.append(
                        "clagd-args %s" % (" ".join(clagArgs)))

        # Create an iteration of /24 networks
        ipsubnets = IPv4Network(u"11.0.0.0/8").subnets(16)
        routersubnets = IPv4Network(u"12.0.0.0/8").subnets(16)
        ip6subnets = IPv6Network(u"2001:aa::/48").subnets(16)
        vlan_subnets = {}
        vlan_ip6subnets = {}
        vip = {}
        vip6 = {}
        rint_subnets = {}
        for vlanidx in range(_VLAN_BASE, _VLAN_BASE + _NUM_VLANS):
            vlan_subnet = next(ipsubnets)
            vlan_subnets[vlanidx] = [vlan_subnet, vlan_subnet.hosts()]
            vlan_ip6subnet = next(ip6subnets)
            vlan_ip6subnets[vlanidx] = [vlan_ip6subnet, vlan_ip6subnet.hosts()]
        # Go through all of the nodes, adding interfaces (bridges, bonds, VLAN
        # sub-interfaces, etc.)
        for node in self.nodes():
            if node.role == "ChardSwitch":
                # For switches, create a single-port bond for each DownLink/Access ports
                bondIdx = 1 if node.swNum == 1 else 11
                mlagBond = []
                node_ifaces = node.config.get_swp_interfaces().values()

                for iface in node_ifaces[3:]:
                    if self.p1c1h1_dual_link_bond and iface == node_ifaces[3]:
                        configure_bond(node, bondIdx, "MlagBond", [IPv4Network(u"0.0.0.0/32")],
                                       [node_ifaces[2], iface], 0, "802.3ad")
                    else:
                        configure_bond(node, bondIdx,  "MlagBond", [IPv4Network(u"0.0.0.0/32")],
                                       [iface], 0, "802.3ad")
                    bondIdx += 1

                log.info("Create a bond for the two ISL ports")
                if self.p1c1h1_dual_link_bond:
                    sub_int = node.config.add_mlag_peerlink(
                        peerlink_slave_objs=[node_ifaces[1]])
                else:
                    sub_int = node.config.add_mlag_peerlink(
                        peerlink_slave_objs=[node_ifaces[1], node_ifaces[2]])
                bondIdx += 1
                sub_int.role = "MgmtVlan"
                IslBondName = sub_int.name

                log.info("Add bridges with VLAN filtering enabled.")
                brifs = node.config.get_bond_interfaces().values()
                bridge_obj = configure_bridge(
                    node, "newDrBridge", [IPv4Network(u"0.0.0.0/32")], brifs, 0, True)
                bridge_obj.eni_snippet.append("bridge-stp on")
                #bridge_obj.eni_snippet.append("bridge-vids %s-%s" % (_VLAN_BASE, _VLAN_BASE + _NUM_VLANS))
                bridge_obj.eni_snippet.append(
                    "bridge-pvid %s" % (_NATIVE_VLAN))
                bridge_obj.eni_snippet.append(
                    "post-up sysctl -w net.ipv4.neigh.default.gc_thresh1=4096")
                bridge_obj.eni_snippet.append(
                    "post-up sysctl -w net.ipv4.neigh.default.gc_thresh2=8192")
                bridge_obj.eni_snippet.append(
                    "post-up sysctl -w net.ipv4.neigh.default.gc_thresh3=8192")
                #bridge.cmds.append("bridge-stp on")

                for vlanidx in range(_VLAN_BASE, _VLAN_BASE + _NUM_VLANS):
                    if node.subrole == "vrr1":
                        vip[vlanidx] = "%s/%s" % (next(vlan_subnets[vlanidx][1]),
                                                  vlan_subnets[vlanidx][0].prefixlen)
                        vip6[vlanidx] = "%s/%s" % (next(vlan_ip6subnets[vlanidx][1]),
                                                   vlan_ip6subnets[vlanidx][0].prefixlen)
                    addr = "%s/%s" % (next(vlan_subnets[vlanidx][1]),
                                      vlan_subnets[vlanidx][0].prefixlen)
                    addr6 = "%s/%s" % (
                        next(vlan_ip6subnets[vlanidx][1]), vlan_ip6subnets[vlanidx][0].prefixlen)
                    sub_intf = configure_vlan(node, bridge_obj, vlanidx, [
                                              addr, addr6], "BridgeVlan")
                    configure_vrr(node, sub_intf, "00:00:5e:00:01:01", [
                                  vip[vlanidx], vip6[vlanidx]])

        for node in self.nodes():
            if node.role == "Server":
                log.info("For servers, create a bond for the two access ports")
                node_ifaces = node.config.get_swp_interfaces().values()
                bond_intf = configure_bond(node, 0, "AccessBond", [IPv4Network(u"0.0.0.0/32")],
                                           node_ifaces, 0, "802.3ad")

                log.info("Add VLANs to the bond")
                for vlanidx in range(_VLAN_BASE, _VLAN_BASE + _NUM_VLANS):
                    addr = "%s/%s" % (next(vlan_subnets[vlanidx][1]),
                                      vlan_subnets[vlanidx][0].prefixlen)
                    addr6 = "%s/%s" % (
                        next(vlan_ip6subnets[vlanidx][1]), vlan_ip6subnets[vlanidx][0].prefixlen)
                    siface = configure_sub_interface(node, vlan_id=vlanidx, role="AccessVlan", address=[
                                                     IPv4Interface(addr), IPv6Interface(addr6)], iface=bond_intf)
                    siface.ip.gateway.append(
                        IPv6Address(vip6[vlanidx].split('/')[0]))
                    if vlanidx == _VLAN_BASE:
                        siface.eni_snippet.append(
                            "post-up ip route del default || true")
                        siface.eni_snippet.append(
                            "post-up ip -6 route del default || true")
                        siface.eni_snippet.append(
                            "post-up ip route add 192.168.0.0/16 via 192.168.0.2 dev eth0")
                        siface.eni_snippet.append("post-up ip route add default via %s dev bond0.%s" %
                                                  (vip[vlanidx].split('/')[0], vlanidx))
                        siface.eni_snippet.append("post-up ip -6 route add default via %s dev bond0.%s" %
                                                  (vip6[vlanidx].split('/')[0], vlanidx))
                    siface.eni_snippet.append(
                        "post-up systemctl stop neighmgrd")

            elif node.role == "router":
                router_ips = []
                # Configuring IPs for Router(R1) interfaces
                for iface in node.config.get_swp_interfaces().values():
                    rint_subnets = next(routersubnets)
                    rint_hosts = rint_subnets.hosts()
                    addr = "%s/%s" % (next(rint_hosts), rint_subnets.prefixlen)
                    iface.ip.address.append(addr)
                    neighbors = get_neighbors(iface)
                    if len(neighbors) != 1:
                        log.info(
                            "The interface %s should only have a single neighbor. It has %d: %s" %
                            (iface.name, len(neighbors), neighbors))
                        sys.exit(1)
                    neighbor = neighbors.pop()
                    niface = iface.opposite
                    rip = next(rint_hosts)
                    router_ips.append(rip)
                    addr = "%s/%s" % (rip, rint_subnets.prefixlen)
                    niface.ip.address.append(addr)

            elif node.role == "rserver":
                ifaces = node.config.get_swp_interfaces().values()[0]
                gw = str(IPv4Interface(ifaces.opposite.ip.address[0]).ip)
                ifaces.eni_snippet.append(
                    "post-up ip route del default || true")
                ifaces.eni_snippet.append(
                    "post-up ip route add 192.168.0.0/16 via 192.168.0.2 dev eth0")
                ifaces.eni_snippet.append(
                    "post-up ip route add default via %s dev %s" % (gw, ifaces.name))

            elif node.role == "ChardSwitch":
                # Config is already done for clag nodes.
                pass
            # For anything else, I don't know how to handle it
            else:
                assert False, 'Cannot handle node %s with role %s' % (
                    node.name, node.role)
        add_mlag_config(router_ips)

        for node in self.nodes():

            if node.role == "ChardSwitch" or node.role == 'router':
                ospf_config = node.config.add_router()
                ospf_config.ospf.enable = 'on'
                ospf_config.ospf.router_id = str(IPv4Address(node.number))
                vrf_config = node.config.add_vrf("default")
                vrf_config.router.ospf.enable = 'on'
                vrf_config.router.ospf.router_id = 'auto'
                vrf_config.router.ospf.redistribute.connected.enable = 'on'
			
                for iface in node.config.get_swp_interfaces().values():
                    if node.role == 'router' or (node.role == "ChardSwitch" and iface.role == 'Uplink'):
                        iface.router.ospf.area = '0.0.0.0'
                        iface.router.ospf.network_type = "point-to-point"

        def configure_topo_post_boot(self):
            # Debug
            for node in self.nodes():
                if node.role == 'ChardSwitch':
                    if node.name == 'p1c1s1':
                        node.device.sudo(
                            "sed -i 's/clagd-backup-ip 12.0.2.2/clagd-backup-ip 12.0.2.2 vrf vrf1/g' /etc/network/interfaces")
                    else:
                        node.device.sudo(
                            "sed -i 's/clagd-backup-ip 12.0.1.2/clagd-backup-ip 12.0.1.2 vrf vrf1/g' /etc/network/interfaces")
                    node.device.sudo("ifreload -a")
            print("Done")


class VrrVrfVaBrConfig(ClagVrrNewBridgeDriverConfig):

    def configure_topo(self):
        ClagVrrNewBridgeDriverConfig.configure_topo(self)
        rid = 1
        for node in self.nodes():
            if node.role == 'ChardSwitch' or node.role == 'router':
                node.asn = 300
                node.rid = '1.1.0.%s' % rid
                rid += 1

            if node.role == 'ChardSwitch':
                # Create two vrfs (vrf1 and vrf2)
                for vrf in range(1, 3):
                    vrf_temp = node.config.add_vrf("vrf"+str(vrf))
                    vrf_temp.role = "vrf"
                bridge_intf = [
                    br for br in node.config.interfaces.values() if hasattr(br, 'role')]
                bridges = [br for br in bridge_intf if 'Bridge' in br.role]
                # adding vrf1 in br100 and br101.
                for br in bridges[1:3]:
                    br.ip.vrf = 'vrf1'
                # adding vrf2 in br102 and br103.
                for br in bridges[3:5]:
                    br.ip.vrf = 'vrf2'
                # adding uplink interface to vrf1.
                node.config.get_swp_interfaces().values()[0].ip.vrf = 'vrf1'
                vrf_ifaces = node.config.get_swp_interfaces().values()
                nei1_ip = str(IPv4Interface(
                    vrf_ifaces[0].opposite.ip.address[0]).ip)
                peer_node = vrf_ifaces[1].opposite.node
                nei2_ip = peer_node.config.get_mlag_peerlink_subinterfaces().values()
                nei2_ip = str(nei2_ip[0].ip.address[0].ip)
                user_vrf = node.config.add_vrf(name='vrf1')
                rtr_obj = node.config.add_router()
                rtr_obj.bgp.enable = "on"
                rtr_obj.bgp.autonomous_system = node.asn
                rtr_obj.bgp.router_id = IPv4Address(u"{}".format(node.rid))
                bgp = user_vrf.router.bgp
                bgp.address_family.ipv4_unicast.enable = 'on'
                bgp.address_family.ipv4_unicast.redistribute.connected.enable = 'on'
                for ip in [nei1_ip, nei2_ip]:
                    port_bgp_obj = user_vrf.router.bgp.add_neighbor(
                        neighbor_id=str(ip))
                    port_bgp_obj.remote_as = 'internal'

                for bridge in node.config.get_sub_interfaces().values():
                    bridge_net = str(IPv4Interface(
                        bridge.ip.address[0]).network)
                    bgp.address_family.ipv4_unicast.add_network(
                        str(bridge_net))

            if node.role == 'router':
                vrf_ifaces = node.config.get_swp_interfaces().values()
                nei1_ip = str(IPv4Interface(
                    vrf_ifaces[1].opposite.ip.address[0]).ip)
                nei2_ip = str(IPv4Interface(
                    vrf_ifaces[2].opposite.ip.address[0]).ip)

                all_vrf = node.config.get_vrf_interfaces()
                vrf_bgp = all_vrf.get('default', None)
                if not vrf_bgp:
                    vrf_bgp = node.config.add_vrf(name='default')
                vrf_bgp.router.bgp.enable = 'on'
                bgp_rtr = node.config.add_router()

                bgp_rtr.bgp.autonomous_system = node.asn
                vrf_bgp.router.bgp.router_id = IPv4Address(
                    (u"{}".format(node.rid)))
                for ip in [nei1_ip, nei2_ip]:
                    neigh = vrf_bgp.router.bgp.add_neighbor(
                        neighbor_id=str(ip))
                    neigh.remote_as = 'internal'

                for inte in node.config.get_swp_interfaces().values():
                    inte_net = str(IPv4Interface(inte.ip.address[0]).network)
                    vrf_bgp.router.bgp.address_family.ipv4_unicast.add_network(
                        inte_net)


class CueClagStaticBondsVaConfig(ClagVRRDualLinkBondSpec, ClagVrrNewBridgeDriverConfig):

    def __init__(self):
        ClagVRRDualLinkBondSpec.__init__(self)
        Topology.__init__(self)
        for nvue_node in list(self.G.keys()):
            nvue_node.config_enabled = True

    def configure_topo(self):
        ClagVrrNewBridgeDriverConfig.configure_topo(self)
 
        def add_bond(node, bond_idx, name_prefix, role, addrs, slaves, mode):
            bond = node.config.add_bond_interface(
                name=name_prefix+str(bond_idx))
            bond.bond.role = role

            bond.ip.address.append(IPv4Interface(u"{}".format(str(addrs))))
            bond.bond.mode = mode
            bond.bond.members.extend(slaves)
            bond.router.ospf.enable = 'on'
            bond.router.ospf.area = '0.0.0.0'
            bond.router.ospf.network_type = "point-to-point"

        for node in self.nodes():
            if node.role == 'ChardSwitch':
                bond_interfaces = [iface for iface in node.config.get_bond_interfaces().values()
                                   if "peerlink" not in iface.name and iface.bond.role == "MlagBond"]
                for iface in bond_interfaces:
                    if hasattr(iface.bond, 'role'):
                        if iface.bond.role == 'MlagBond':
                            iface.bond.mode = "static"

                add_bond(node, 1, 'uplink', 'uplink', node.config.get_swp_interfaces().values()[0].ip.address[0],
                         [node.config.get_swp_interfaces().values()[0]], 'static')
                node.config.get_swp_interfaces().values()[0].ip.address.pop()
                ospf_config = node.config.add_router()
                ospf_config.ospf.enable = 'on'
                ospf_config.ospf.router_id = str(IPv4Address(node.number))
                vrf_config = node.config.add_vrf("default")
                vrf_config.router.ospf.enable = 'on'
                vrf_config.router.ospf.router_id = 'auto'
                vrf_config.router.ospf.redistribute.static.enable = 'on'
                vrf_config.router.ospf.redistribute.connected.enable = 'on'

            elif node.role == 'Server':
                bond_interfaces = [iface for iface in node.config.get_bond_interfaces().values()
                                   if "peerlink" not in iface.name and iface.bond.role == "AccessBond"]
                for iface in bond_interfaces:
                    if hasattr(iface.bond, 'role'):
                        if iface.bond.role == 'AccessBond':
                            iface.bond.mode = "static"

            elif node.role == 'router':
                add_bond(node, 1, 'downlink', 'downlink', node.config.get_swp_interfaces().values()[1].ip.address[0],
                         [node.config.get_swp_interfaces().values()[1]], 'static')
                add_bond(node, 2, 'downlink', 'downlink', node.config.get_swp_interfaces().values()[2].ip.address[0],
                         [node.config.get_swp_interfaces().values()[2]], 'static')
                node.config.get_swp_interfaces().values()[1].ip.address.pop()
                node.config.get_swp_interfaces().values()[2].ip.address.pop()
                ospf_config = node.config.add_router()
                ospf_config.ospf.enable = 'on'
                ospf_config.ospf.router_id = str(IPv4Address(node.number))
                vrf_config = node.config.add_vrf("default")
                vrf_config.router.ospf.enable = 'on'
                vrf_config.router.ospf.router_id = 'auto'
                vrf_config.router.ospf.redistribute.static.enable = 'on'
                vrf_config.router.ospf.redistribute.connected.enable = 'on'


class CueLacpBypassClagConfig(CueClagStaticBondsVaConfig):
    def configure_topo(self):
        CueClagStaticBondsVaConfig.configure_topo(self)
        self._VLAN_BASE=100
        for node in self.nodes():
            if node.role == 'ChardSwitch':
                bond_interfaces = [iface for iface in node.config.get_bond_interfaces().values()
                                   if "peerlink" not in iface.name and iface.bond.role == "MlagBond"]
                for iface in bond_interfaces:
                    if hasattr(iface.bond, 'role'):
                        if iface.bond.role == 'MlagBond':
                            iface.bond.mode = "lacp"
                            iface.bond.lacp_bypass = "on"

            elif node.role == 'Server':
                bond_interfaces = [iface for iface in node.config.get_bond_interfaces().values()
                                   if "peerlink" not in iface.name and iface.bond.role == "AccessBond"]
                for iface in bond_interfaces:
                    if hasattr(iface.bond, 'role'):
                        if iface.bond.role == 'AccessBond':
                            iface.bond.mode = "lacp"


if __name__ == '__main__':

    choice_str = """
             Please Enter Number to Simulate Type of Topology:
             1. Clag VRR Vlan Aware Bridge model Config.
             2. VRR VRF Vlan Aware Bridge model Config.
             3. Clag with static bonds VA Bridge Config.
             4. Clag with lacp bypass .
             """
    choice = {
        1: ClagVrrNewBridgeDriverConfig(),
        2: VrrVrfVaBrConfig(),
        3: CueClagStaticBondsVaConfig(),
        4: CueLacpBypassClagConfig()
    }
    print(choice_str)
    for re_try in range(4):
        try:
            elected_choice = int(
                input("Enter Topo Number as Choice (0 for default action) :- "))
            break
        except Exception as exc:
            print(
                'Sorry Only Numbers and if u give invalid number you will get 1 options')
            continue

    topo = choice.get(elected_choice, ClagVrrNewBridgeDriverConfig())
    topo.class_filename = os.path.basename(__file__).split('.')[0]
    topo.run_from_command_line()
