from autolib.sleep import sleep
from test_files.lib.base import WithTopo
from test_files.configs.RadiusConfig import RadiusConfig
from nose.plugins.attrib import attr
from autolib.dictlib import AttrDict
from random import randint
import time
from autolib.netobjects import NetworkDevice
# from fabric2.context_managers import settings
# from fabric.state import commands, connections
from fabric2 import Connection, Config, task
from autolib.logutils import getLogger
from ipaddress import IPv4Network, IPv6Network, IPv4Network, IPv6Interface, ip_address, ip_network, IPv4Address, \
    IPv4Interface
import re

log = getLogger(__name__)


def login_cumulus(self, node):
    if node.hard_target:
        sw_ob = NetworkDevice(node.hard_target.hostname, user='cumulus', password='CumulusLinux!')
    else:
        ssh_port1 = self.topo.ssh_port(node)
        sw_ob = NetworkDevice('localhost', port=ssh_port1, user='cumulus', password='CumulusLinux!')
    return sw_ob


def wait_for_netd(node):
    max_wait = 30
    for wait in range(1, max_wait + 1):
        out = node.device.sudo("net show system ", warn_only=True)
        if re.search("ERROR", out):
            sleep(1)
            continue
        break
    if wait >= max_wait:
        assert False, "Timeout waiting for netd"

    log.info("netd restart took %d seconds" % (wait - 1))


def write_freeradius_users_conf(device, data_list):
    # this function writes radius users config with data provided
    try:
        device.sudo("echo '%s' >> /etc/freeradius/3.0/users" % (data_list))
    except Exception:
        pass


def write_freeradius_client_conf(device, data_list):
    # this function writes radius client config with data provided
    try:
        device.sudo("echo '%s' >> /etc/freeradius/3.0/clients.conf" % (data_list))
    except Exception:
        pass


def config_freeradius(radius, ip_addr, secret, user_list, ipv6=False):
    data = 'client %s {\n' % (ip_addr)
    data += '\t ipaddr =%s\n' % (ip_addr)
    data += '\t secret = %s\n' % secret
    data += '}\n'

    write_freeradius_client_conf(radius.device, data)

    data = "\n"
    for user in user_list:
        data += user + "\n"

    write_freeradius_users_conf(radius.device, data)

    if ipv6:
        radius.device.sudo("sed -i 's/ipaddr =/\#ipaddr =/g' /etc/freeradius/3.0/radiusd.conf", warn_only=True)
        radius.device.sudo("sed -i 's/\#.*ipv6addr =/        ipv6addr =/g' /etc/freeradius/3.0/radiusd.conf",
                           warn_only=True)

    # restart the freeradius service
    radius.device.service.restart('freeradius')


def install_freeradius(node):
    repos = ('deb  http://deb.debian.org/debian buster main contrib non-free',
             'deb-src  http://deb.debian.org/debian buster main contrib non-free',
             'deb  http://deb.debian.org/debian buster-updates main contrib non-free',
             'deb-src  http://deb.debian.org/debian buster-updates main contrib non-free',
             'deb http://security.debian.org/debian-security buster/updates main contrib non-free',
             'deb-src http://security.debian.org/debian-security buster/updates main contrib non-free')

    node.device.install_pkg('freeradius', repos=repos)


class TestRadiusClient(WithTopo):
    topo_class = RadiusConfig
    test_owner = "sumgupta"
    hard_node_guide = {'switch': 'switch'}
    hard_node_required = True
    timeout = 3000

    @classmethod
    def pre_suite_hook(self):
        log.info("*" * 30 + 'Running pre_suite_hook' + "*" * 30)

        sut = self.topo.switch
        srv1 = self.topo.host1
        srv2 = self.topo.host2

        sut.device.sudo("cp /etc/shadow /etc/shadow.orig", warn_only=True)
        sut.device.sudo("cp /etc/passwd /etc/passwd.orig", warn_only=True)
        sut.device.sudo("cp /etc/group  /etc/group.orig", warn_only=True)

        # Install free radius on host1 and host2

        self.vrf = 'mgmt'
        self.local_usr = 'cumulus'
        self.local_usr_pw = 'CumulusLinux!'
        self.radius_adm1 = 'sysadmin1'
        self.radius_adm1_pw = 'Passw0rd!'
        self.radius_usr1 = 'sysoper1'
        self.radius_usr1_pw = 'CumulusLinux!'
        self.radius_usr2 = 'sysoper2'
        self.radius_usr2_pw = 'oper1'
        self.radius_usr3 = 'sysoper3'
        self.radius_usr3_pw = 'oper3'
        self.radius_priv = 'syspriv'
        self.radius_priv_pw = 'priv'

        sut.vlan_ip = "11.0.0.9"
        sut.vlan_ipv6 = u"2011:10:1:2::9/64"

        # sut.lo.addrs    = u"12.0.0.9/32"
        sut.lo.addrs_ip = "12.0.0.9"

        bridge = sut.config.add_bridge("br_default")
        sut_ifaces = list(sut.config.get_swp_interfaces().values())[:3]
        for swp_obj in sut_ifaces:
            swp_br = swp_obj.add_bridges(bridge.name)
        svi_temp = sut.config.add_svi_interface("vlan" + str(1))
        svi_temp.base_interface = bridge
        svi_temp.vlan = 1
        svi_temp.ip.address.append(IPv4Interface(u"11.0.0.9/24"))
        svi_temp.ip.address.append(IPv6Interface(sut.vlan_ipv6))
        loop_iface = sut.config.add_loopback_interface("lo")
        loop_iface.ip.address.append(IPv4Interface(u"12.0.0.9/32"))

        sut.config.render_full_config()
        sut.device.sudo("nv config apply startup -y")

        srv1.secret = "srv1_secret"
        self.srv1_users = [
            '%s Cleartext-Password := %s' % (self.radius_adm1, self.radius_adm1_pw),
            '%s Cleartext-Password := %s' % (self.radius_usr1, self.radius_usr1_pw),
            '%s Cleartext-Password := bad%s' % (self.radius_usr2, self.radius_usr2_pw),

            '%s0 Cleartext-Password := %s0' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair += \\"shell:priv-lvl=0\\"',
            '%s1 Cleartext-Password := %s1' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair = \\"shell:priv-lvl=1\\"',
            '%s2 Cleartext-Password := %s2' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair = \\"shell:priv-lvl=2\\"',
            '%s3 Cleartext-Password := %s3' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair = \\"shell:priv-lvl=3\\"',
            '%s4 Cleartext-Password := %s4' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair = \\"shell:priv-lvl=4\\"',
            '%s5 Cleartext-Password := %s5' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair = \\"shell:priv-lvl=5\\"',
            '%s6 Cleartext-Password := %s6' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair = \\"shell:priv-lvl=6\\"',
            '%s7 Cleartext-Password := %s7' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair = \\"shell:priv-lvl=7\\"',
            '%s8 Cleartext-Password := %s8' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair = \\"shell:priv-lvl=8\\"',
            '%s9 Cleartext-Password := %s9' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair = \\"shell:priv-lvl=9\\"',
            '%s10 Cleartext-Password := %s10' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair = \\"shell:priv-lvl=10\\"',
            '%s11 Cleartext-Password := %s11' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair = \\"shell:priv-lvl=11\\"',
            '%s12 Cleartext-Password := %s12' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair = \\"shell:priv-lvl=12\\"',
            '%s13 Cleartext-Password := %s13' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair = \\"shell:priv-lvl=13\\"',
            '%s14 Cleartext-Password := %s14' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair = \\"shell:priv-lvl=14\\"',
            '%s15 Cleartext-Password := %s15' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair = \\"shell:priv-lvl=15\\"',
        ]

        srv2.secret = "srv2_secret"
        self.srv2_users = [
            '%s Cleartext-Password := %s' % (self.radius_adm1, self.radius_adm1_pw),
            '%s Cleartext-Password := %s' % (self.radius_usr1, self.radius_usr1_pw),
            '%s Cleartext-Password := %s' % (self.radius_usr2, self.radius_usr2_pw),
            '%s Cleartext-Password := %s' % (self.radius_usr3, self.radius_usr3_pw),
            '%s0 Cleartext-Password := %s0' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair += \\"shell:priv-lvl=0\\"',
            '%s1 Cleartext-Password := %s1' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair = \\"shell:priv-lvl=1\\"',
            '%s2 Cleartext-Password := %s2' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair = \\"shell:priv-lvl=2\\"',
            '%s3 Cleartext-Password := %s3' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair = \\"shell:priv-lvl=3\\"',
            '%s4 Cleartext-Password := %s4' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair = \\"shell:priv-lvl=4\\"',
            '%s5 Cleartext-Password := %s5' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair = \\"shell:priv-lvl=5\\"',
            '%s6 Cleartext-Password := %s6' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair = \\"shell:priv-lvl=6\\"',
            '%s7 Cleartext-Password := %s7' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair = \\"shell:priv-lvl=7\\"',
            '%s8 Cleartext-Password := %s8' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair = \\"shell:priv-lvl=8\\"',
            '%s9 Cleartext-Password := %s9' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair = \\"shell:priv-lvl=9\\"',
            '%s10 Cleartext-Password := %s10' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair = \\"shell:priv-lvl=10\\"',
            '%s11 Cleartext-Password := %s11' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair = \\"shell:priv-lvl=11\\"',
            '%s12 Cleartext-Password := %s12' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair = \\"shell:priv-lvl=12\\"',
            '%s13 Cleartext-Password := %s13' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair = \\"shell:priv-lvl=13\\"',
            '%s14 Cleartext-Password := %s14' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair = \\"shell:priv-lvl=14\\"',
            '%s15 Cleartext-Password := %s15' % (self.radius_priv, self.radius_priv_pw),
            '  Cisco-AVpair = \\"shell:priv-lvl=15\\"',
        ]

        # Install free radius on host1 and host2

        log.info("Installing freeradius server on host1")
        install_freeradius(srv1)
        config_freeradius(srv1, sut.vlan_ip, srv1.secret, self.srv1_users)

        log.info("Installing freeradius server on host2")
        install_freeradius(srv2)
        config_freeradius(srv2, sut.vlan_ipv6, srv2.secret, self.srv2_users, ipv6=True)

        # Install packages required for radius client on sut

        log.info("Installing radius client packages on %s" % sut.device.hostname)

        # repos = ('deb http://cl4-repo.mvlab.cumulusnetworks.com/dev CumulusLinux-4-updates cumulus upstream',
        #         'deb-src http://cl4-repo.mvlab.cumulusnetworks.com/dev CumulusLinux-4-updates cumulus upstream')
        repos = ('deb http://stage-repo4.cumulusnetworks.com/repo CumulusLinux-4-updates cumulus upstream',
                 'deb-src http://stage-repo4.cumulusnetworks.com/repo CumulusLinux-4-updates cumulus upstream')

        sut.device.install_pkg(('libnss-mapuser', 'libpam-radius-auth'), repos=repos)

        # netd needs to be restated after installing libnss
        log.info("Restarting netd")
        sut.device.sudo("systemctl reset-failed ; systemctl restart netd.service")

        # netd might take a few seconds until it is ready. It takes longer
        # on some platforms. Wait here until we can connect to netd.
        wait_for_netd(sut)

        # Save a copy of the original installed pam_radius_auth.conf and nss_mapuser.conf to restore between tests

        sut.device.sudo('echo "vrf-name vlan1"  >> /etc/pam_radius_auth.conf')
        sut.device.sudo("cp /etc/pam_radius_auth.conf /tmp/pam_radius_auth.conf")
        sut.device.sudo("cp /etc/nss_mapuser.conf /tmp/nss_mapuser.conf")

        sut.device.sudo("cp /etc/shadow /etc/shadow.test", warn_only=True)
        sut.device.sudo("cp /etc/passwd /etc/passwd.test", warn_only=True)
        sut.device.sudo("cp /etc/group  /etc/group.test", warn_only=True)
        sut.device.sudo('cp /etc/nginx/sites-available/nvue.conf /etc/nginx/sites-available/nvue-test.conf',
                        warn_only=True)
        sut.device.sudo('rm  /etc/nginx/sites-enabled/nginx-restapi.conf', warn_only=True)
        sut.device.sudo('ln -s /etc/nginx/sites-available/nvue-test.conf /etc/nginx/sites-enabled/nginx-restapi.conf',
                        warn_only=True)
        sut.device.sudo('cat  /etc/nginx/sites-enabled/nginx-restapi.conf', warn_only=True)

        sut.device.sudo('systemctl reset-failed', warn_only=True)
        sut.device.sudo('systemctl restart nginx', warn_only=True)

        # create sudoers file to allow sudo for admin user
        sut.device.sudo("echo %s' ALL=(ALL:ALL) ALL' > /etc/sudoers.d/%s" % (self.radius_adm1, self.radius_adm1),
                        warn_only=True)

        log.info("*" * 30 + 'Finished pre_suite_hook' + "*" * 30)

    def pre_run_hook(self):
        log.info("*" * 30 + 'Running pre_run_hook' + "*" * 30)

        sut = self.topo.switch
        srv1 = self.topo.host1
        srv2 = self.topo.host2

        srv1_ifaces = list(srv1.config.get_swp_interfaces().values())
        srv2_ifaces = list(srv2.config.get_swp_interfaces().values())

        # links to radius servers show be up at start of all tests
        srv1.device.sudo('ip link set %s up' % srv1_ifaces[0].name)
        srv2.device.sudo('ip link set %s up' % srv2_ifaces[0].name)
        sleep(2)
        # remove existing connections
        for i in range(0, 16):
            username = "%s%s" % (self.radius_priv, str(i))
            if i == 16:
                username = 'cumulus'
            try:
                if sut.hard_target:
                    c = Connection('%s@%s:22' % (username, sut.hard_target.hostname))
                    if c is not None:
                        c.close()
                # else:
                #     del connections['%s@localhost:%s' % (username, ssh_port1)]
            except Exception as e:
                log.debug("%s connection does not exist" % username)
            else:
                log.info("removed connection for %s" % username)

        # Start all tests with ONLY our entries in pam_radius_auth.conf
        sut.device.sudo("cp /tmp/nss_mapuser.conf /etc/nss_mapuser.conf")
        sut.device.sudo("cp /tmp/pam_radius_auth.conf /etc/pam_radius_auth.conf")
        sut.device.sudo(
            "echo '%s %s' >> /etc/pam_radius_auth.conf" % (str(srv1_ifaces[0].ip.address[0].ip), srv1.secret))
        sut.device.sudo(
            "echo '[%s] %s' >> /etc/pam_radius_auth.conf" % (str(srv2_ifaces[0].ip.address[1].ip), srv2.secret))
        sut.device.sudo("cp /etc/passwd.test /etc/passwd", warn_only=True)
        sut.device.sudo("cp /etc/shadow.test /etc/shadow", warn_only=True)
        sut.device.sudo("cp /etc/group.test /etc/group", warn_only=True)

        # if vrf is configured from a previous test, remove it
        out = sut.device.sudo('grep "vrf %s" /etc/network/interfaces | wc -l' % self.vrf, warn_only=True)

        if self.vrf == "mgmt":
            log.info("Will not remove vrf %s" % self.vrf)
        else:
            sut.device.sudo('net del vrf %s' % self.vrf, warn_only=True)
            sut.device.sudo('net commit', warn_only=True)
            log.info("Removing vrf %s" % self.vrf)

        # if radius server was configured for loopback address from previous test, fix it
        out = srv1.device.sudo('grep "%s" /etc/freeradius/3.0/clients.conf | wc -l' % sut.lo.addrs_ip, warn_only=True)
        if int(out) == 1:
            log.info("Removing loopback ip from /etc/freeradius/3.0/clients.conf")
            srv1.device.sudo("sed -i 's/%s/%s/g' /etc/freeradius/3.0/clients.conf" % (sut.lo.addrs_ip, sut.vlan_ip),
                             warn_only=True)
            srv1.device.service.restart('freeradius')

        for i in range(0, 16):
            sut.device.sudo("rm -rf /home/%s" % '%s%s' % (self.radius_priv, str(i)), warn_only=True)

        # netd needs to be restated if mapped_priv_user has changed
        log.info("Restarting netd")
        sut.device.sudo("systemctl reset-failed ; systemctl restart netd.service")

        # netd might take a few seconds until it is ready. It takes longer
        # on some platforms. Wait here until we can connect to netd.
        wait_for_netd(sut)

        log.info("*" * 30 + 'Finished pre_run_hook' + "*" * 30)

    @classmethod
    def post_suite_hook(self):
        log.info("*" * 30 + 'Running post_suite_hook' + "*" * 30)

        sut = self.topo.switch

        if sut.hard_target:
            # remove file we created
            # sut.device.sudo("rm -rf /etc/sudoers.d/%s" % self.radius_adm1, warn_only=True)

            # sut.device.sudo("cp /tmp/pam_radius_auth.conf /etc/pam_radius_auth.conf")
            # uninstall radius client

            sut.device.sudo('apt-get purge libnss-mapuser libpam-radius-auth -y', warn_only=True)
            sut.device.sudo('apt-get autoremove --purge -y', warn_only=True)

            # remove created directories

            sut.device.sudo("rm -rf /home/%s" % self.radius_adm1, warn_only=True)
            sut.device.sudo("rm -rf /home/%s" % self.radius_usr1, warn_only=True)
            sut.device.sudo("rm -rf /home/%s" % self.radius_usr2, warn_only=True)
            sut.device.sudo("rm -rf /home/%s" % self.radius_usr3, warn_only=True)
            for i in range(0, 16):
                sut.device.sudo("rm -rf /home/%s" % '%s%s' % (self.radius_priv, str(i)), warn_only=True)

            sut.device.sudo("rm -rf /home/%s" % 'radius_priv_user', warn_only=True)
            sut.device.sudo("rm -rf /home/%s" % 'radius_user', warn_only=True)
            sut.device.sudo("rm -rf /home/%s" % 'cumulus_priv_user', warn_only=True)

            sut.device.sudo("cp /etc/shadow.orig /etc/shadow", warn_only=True)
            sut.device.sudo("cp /etc/passwd.orig /etc/passwd", warn_only=True)
            sut.device.sudo("cp /etc/group.orig  /etc/group", warn_only=True)
            sut.device.sudo("rm /etc/shadow.orig", warn_only=True)
            sut.device.sudo("rm /etc/passwd.orig", warn_only=True)
            sut.device.sudo("rm /etc/group.orig", warn_only=True)

        log.info("*" * 30 + 'Finished post_suite_hook' + "*" * 30)

    @attr(tags=['smoke', 'nightly', 'radius', 'fw-smoke'])
    @WithTopo._handle_errors
    def test_01_user_auth_ssh(self):

        """
        Name: user_auth_ssh
        ====

        Description:
        ============
           Verify only users who are able to authenticate with radius server
           (except local user accounts) are able to login to the switch,
           access should be denied for others.

        Steps:
        ============
         1. Login to the switch with valid user who has account in radius.
         2. Verify login is successful.
         3. Try to login with same user with wrong password.
         4. Verify access is denied.
         5. Try to login with non existing username in radius server.
         6. Verify access is denied.
         7. Verify local users have access to switch.

        Result:
        ============
        Only valid users should get access to switch.
        """

        sut = self.topo.switch
        srv1 = self.topo.host1
        srv2 = self.topo.host2

        srv2_ifaces = list(srv2.config.get_swp_interfaces().values())
        # Keep second server down for this test
        srv2.device.sudo('ip link set %s down' % srv2_ifaces[0].name)

        # Verify the node access with correct credentials.
        verify_node_access(self, sut, self.radius_usr1, self.radius_usr1_pw)

        # Verify the node access with correct username wrong password.
        verify_node_denied(self, sut, self.radius_usr1, 'adminuser')

        # Verify the node access with non existing user.
        verify_node_denied(self, sut, 'cumulus333', 'adminuser')

        # Verify local users have access to switch.
        verify_node_access(self, sut, self.local_usr, self.local_usr_pw)

        check_directory_exists(sut, self.radius_usr1)

    @attr(tags=['nightly', 'radius'])
    @WithTopo._handle_errors
    def test_02_sudo(self):

        """
        Name: sudo
        ====

        Description:
        ============
          For radius, there are no privledge levels. For sudo access. The /etc/suders.d directory must contain
          a file that contains an entry for users that will be allowed sudo access.
          ex:
             sysadmin1 ALL=(ALL:ALL) ALL

          Note: sysadmin user was added to sudoers.d during pre_suite setup. sysoper1 has not
          been added to suders.d. Consequently, admin user should be allowed sudo access. oper
          user should be denied sudp access.

        Stepudo :
        ============
         1. Verify sysadmin1 user can execute sudo commands.
         2. Verify sysoper1 user does not have sudo priviledge.

        Result:
        =======
        Mark the test as failed if any of the above fail.

        """
        sut = self.topo.switch
        srv1 = self.topo.host1
        srv2 = self.topo.host2

        # Verify sysadmin1 is able to execute sudo level commands.
        verify_sudo_access(self, sut, self.radius_adm1, self.radius_adm1_pw)

        # Verify sysadmin1 is able to execute sudo level commands.
        verify_sudo_access(self, sut, self.radius_adm1, self.radius_adm1_pw)

        # Verify sysoper1 is not able to execute sudo level commands.
        verify_sudo_denied(self, sut, self.radius_usr1, self.radius_usr1_pw)

        check_directory_exists(sut, self.radius_adm1)
        check_directory_exists(sut, self.radius_usr1)

    @attr(tags=['nightly', 'radius'])
    @WithTopo._handle_errors
    def test_03_server_not_reachable(self):

        """
        Name: server_not_reachable
        ====

        Description:
        ============
           Verify radius users access is denied when server is not reachable.

        Steps:
        ============
         1. Verify user can access node when both servers are up.
         2. Shut the interfaces on both radius servers to make them unreachable.
         3. Verify user access is denied.
         4. Verify local users have access to switch.
         5. Unshut the interfaces on radius servers to make them reachable.
         6. Verify user is able to access the node.

        Result:
        =======
        Mark the test as failed if any of the above steps are not satisfied.
        """
        sut = self.topo.switch
        srv1 = self.topo.host1
        srv2 = self.topo.host2

        srv1_ifaces = list(srv1.config.get_swp_interfaces().values())
        srv2_ifaces = list(srv2.config.get_swp_interfaces().values())
        # Verify access when servers are up
        verify_node_access(self, sut, self.radius_usr1, self.radius_usr1_pw)

        # verify access is denied when both server are down
        srv1.device.sudo('ip link set %s down' % srv1_ifaces[0].name)
        srv2.device.sudo('ip link set %s down' % srv2_ifaces[0].name)
        verify_node_denied(self, sut, self.radius_usr1, self.radius_usr1_pw)

        # Verify local users have access to switch.
        verify_node_access(self, sut, self.local_usr, self.local_usr_pw)

        # Verify access when server comes back up
        srv1.device.sudo('ip link set %s up' % srv1_ifaces[0].name)
        sleep(2)
        verify_node_access(self, sut, self.radius_usr1, self.radius_usr1_pw)

    @attr(tags=['nightly', 'radius'])
    @WithTopo._handle_errors
    def test_04_server_failover(self):

        """
        Name: server_failover
        ====

        Description:
        ============
           Verify users are authenticated with backup server when primary server is not reachable.

        Steps:
        ============
         1. Verify user is able to access the node.
         2. Shut the interfaces on primary radius server to make it unreachable.
         3. Verify still user is able to access the node using backup server.
         4. Shut the interfaces on backup radius server to make it unreachable.
         5. Verify user access is denied.
         6. unshut the interfaces on primary and backup radius servers to make them reachable.
         7. Verify user is able to access the node.

        Result:
        =======
        (Mark the test as failed if any of the above steps are not satisfied.
        """

        sut = self.topo.switch
        srv1 = self.topo.host1
        srv2 = self.topo.host2

        srv1_ifaces = list(srv1.config.get_swp_interfaces().values())
        srv2_ifaces = list(srv2.config.get_swp_interfaces().values())
        # Verify access when servers are up
        verify_node_access(self, sut, self.radius_usr1, self.radius_usr1_pw)

        # verify access when the first server id down
        srv1.device.sudo('ip link set %s down' % srv1_ifaces[0].name)
        srv2.device.sudo('ip link set %s up' % srv1_ifaces[0].name)
        verify_node_access(self, sut, self.radius_usr1, self.radius_usr1_pw)

        # verify access is denied when both servers are down
        srv2.device.sudo('ip link set %s down' % srv2_ifaces[0].name)
        verify_node_denied(self, sut, self.radius_usr1, self.radius_usr1_pw)

        # Verify local users have access to switch.

        verify_node_access(self, sut, self.local_usr, self.local_usr_pw)
        srv1.device.sudo('ip link set %s up' % srv1_ifaces[0].name)
        srv2.device.sudo('ip link set %s up' % srv2_ifaces[0].name)
        sleep(2)

        verify_node_access(self, sut, self.radius_usr1, self.radius_usr1_pw)

    @attr(tags=['nightly', 'radius'])
    @WithTopo._handle_errors
    def test_05_user_in_sec_server(self):

        """
        Name: user_in_sec_server
        ====

        Description:
        ============
           Verify radius client DOES NOT try second server when first server denies access due
           to user credentials are not found. This is diffent than tacacs which WILL try
           the second server.

        Steps:
        ============
         1. Choose a user who's credentials are only in second radius server.
         2. Bring down interface on first server to make it unreachable.
         3. Verify user can access node via second server.
         4. Bring up first server (with missing credentials)
         5. Verify access is denied by first server.

        Result:
        =======
        Mark the test as failed if any of the above steps are not satisfied.
        """

        sut = self.topo.switch
        srv1 = self.topo.host1
        srv2 = self.topo.host2

        srv1_ifaces = list(srv1.config.get_swp_interfaces().values())
        srv2_ifaces = list(srv2.config.get_swp_interfaces().values())
        # verify access when first server is not reachable
        srv1.device.sudo('ip link set %s down' % srv1_ifaces[0].name)
        verify_node_access(self, sut, self.radius_usr3, self.radius_usr3_pw)

        # verify access is denied when first server is up with missing user in first server
        srv1.device.sudo('ip link set %s up' % srv1_ifaces[0].name)
        sleep(2)
        verify_node_denied(self, sut, self.radius_usr3, self.radius_usr3_pw)

        login_cumulus(self, sut)

    @attr(tags=['nightly', 'radius'])
    @WithTopo._handle_errors
    def test_06_user_credentials_wrong_in_first_server(self):

        """
        Name: user_credentials_wrong_in_first_server
        ====

        Description:
        ============
           Verify radius client DOES NOT try second server when first server denies access due
           to invalid  user credentials. This is diffent than tacacs which WILL try
           the second server.

        Steps:
        ============
         1. Choose a user who's credentials are invalid in first server and valid in second radius server.
         2. Bring down interface on first server to make it unreachable.
         3. Verify user can access node via second server.
         4. Bring up first server (with incorrect credentials)
         5. Verify acces is denied by first server.

        Result:
        =======
        Mark the test as failed if any of the above steps are not satisfied.
        """

        sut = self.topo.switch
        srv1 = self.topo.host1
        srv2 = self.topo.host2

        srv1_ifaces = list(srv1.config.get_swp_interfaces().values())
        srv2_ifaces = list(srv2.config.get_swp_interfaces().values())

        # verify access when first server is not reachable
        srv1.device.sudo('ip link set %s down' % srv1_ifaces[0].name)
        verify_node_access(self, sut, self.radius_usr2, self.radius_usr2_pw)

        # verify access is denied when first server is up with incorrect credentials
        srv1.device.sudo('ip link set %s up' % srv1_ifaces[0].name)
        sleep(2)
        verify_node_denied(self, sut, self.radius_usr2, self.radius_usr2_pw)

        login_cumulus(self, sut)

    @attr(tags=['nightly', 'radius'])
    @WithTopo._handle_errors
    def test_07_wrong_secret_key(self):

        """
        Name: wrong_secret_key
        ====

        Description:
        ============
           Verify user authentication is failed when radius client does not have secret key or have wrong secret key.
           Verify second server will be used when secret key is bad.

        Steps:
        ============
         1. Start with second server down.
         2. Verify user can access node using first server.
         3. Change secret key for first server to a bad secret.
         4. Verify user is denied access due to bad secret.
         5. Bring up second server.
         6. Verify user access via second server.
         7. Change secret key for second server to a bad secret.
         8. Verify access is denied (because no servers are available).
         9. Add a new correct key for second server.
         10. Verify access via second server with correct key.

        Result:
        =======
        Mark the test as failed if any of the above steps are not satisfied.
        """

        sut = self.topo.switch
        srv1 = self.topo.host1
        srv2 = self.topo.host2

        srv1_ifaces = list(srv1.config.get_swp_interfaces().values())
        srv2_ifaces = list(srv2.config.get_swp_interfaces().values())
        # Start with second server down
        srv2.device.sudo('ip link set %s down' % srv2_ifaces[0].name)

        verify_node_access(self, sut, self.radius_usr1, self.radius_usr1_pw)
        sut.device.sudo("sed -i 's/%s/Bad/g' /etc/pam_radius_auth.conf" % srv1.secret, warn_only=True)
        verify_node_denied(self, sut, self.radius_usr1, self.radius_usr1_pw)

        # Bring up second server
        srv2.device.sudo('ip link set %s up' % srv2_ifaces[0].name)
        sleep(2)

        # verify after first server fails with bad password, second server will allow access
        verify_node_access(self, sut, self.radius_usr1, self.radius_usr1_pw)

        sut.device.sudo("sed -i 's/%s/Bad/g' /etc/pam_radius_auth.conf" % srv2.secret, warn_only=True)
        verify_node_denied(self, sut, self.radius_usr1, self.radius_usr1_pw)

        sut.device.sudo(
            "echo '[%s] %s' >> /etc/pam_radius_auth.conf" % (str(srv2_ifaces[0].ip.address[1].ip), srv2.secret))
        verify_node_access(self, sut, self.radius_usr1, self.radius_usr1_pw)

    @attr(tags=['nightly', 'radius'])
    @WithTopo._handle_errors
    def test_08_source_ip(self):

        """
        Name: wrong_secret_key
        ====

        Description:
        ============
           Verify radius client will use source IP address defined per server in/etc/pam_radius_auth.conf
           Verify when authentication fails due to invalid source IP addresss, the second server will be used.

        Steps:
        ============
         1. Start with second server down
         2. Modify radius client to use source ip from loopback address.
         3. Verify user access is denied (because source ip address is not configured in server).
         4. Bring up second server.
         5. Verify user access via second server.
         6. Bring down second server.
         7. Modify freeradius server to accept source ip from loopback address. (requires freeradius restart)
         8. Veriify user access via first server using loopback address.

        Result:
        =======
        Mark the test as failed if any of the above steps are not satisfied.
        """
        sut = self.topo.switch
        srv1 = self.topo.host1
        srv2 = self.topo.host2

        srv1_ifaces = list(srv1.config.get_swp_interfaces().values())
        srv2_ifaces = list(srv2.config.get_swp_interfaces().values())
        loop_addr = str(sut.config.get_loopback_interfaces().get('lo').ip.address[0])
        # srv needs a route to lo addr on sut
        srv1.device.sudo('ip route add %s via %s dev %s' % (loop_addr, sut.vlan_ip, srv1_ifaces[0].name),
                         warn_only=True)

        # Start with second server down
        srv2.device.sudo('ip link set %s down' % srv2_ifaces[0].name)

        verify_node_access(self, sut, self.radius_usr1, self.radius_usr1_pw)

        sut.device.sudo(
            "sed -i 's/%s/%s 3 %s/g' /etc/pam_radius_auth.conf" % (srv1.secret, srv1.secret, sut.lo.addrs_ip),
            warn_only=True)

        verify_node_denied(self, sut, self.radius_usr1, self.radius_usr1_pw)

        # Bring up second server
        srv2.device.sudo('ip link set %s up' % srv2_ifaces[0].name)
        sleep(2)

        verify_node_access(self, sut, self.radius_usr1, self.radius_usr1_pw)

        # Bring down second server
        srv2.device.sudo('ip link set %s down' % srv2_ifaces[0].name)
        sleep(2)

        # change source ip address in free radius server
        srv1.device.sudo("sed -i 's/%s/%s/g' /etc/freeradius/3.0/clients.conf" % (sut.vlan_ip, sut.lo.addrs_ip),
                         warn_only=True)
        srv1.device.service.restart('freeradius')
        sleep(5)

        verify_node_access(self, sut, self.radius_usr1, self.radius_usr1_pw)

    # @attr(tags=['nightly', 'radius'])
    @WithTopo._handle_errors
    def test_09_radius_vrf(self):

        """
        Name: radius_vrf
        ====

        Description:
        ============
           Verify radius client works when vrf is present.

        Steps:
        ============
         1. Configure vrf on radius client.
         2. Punch a hole in defaiut vrf for radius server in mgmt vrf
         3. Verify radius user can be authenticated with the server.

        Result:
        =======
        Mark the test as failed if any of the above steps are not satisfied.
        """
        sut = self.topo.switch
        srv1 = self.topo.host1
        srv2 = self.topo.host2
        srv1_ifaces = list(srv1.config.get_swp_interfaces().values())
        srv2_ifaces = list(srv2.config.get_swp_interfaces().values())

        intf = sut.config.add_vrf(self.vrf)
        intf.eni_snippet.append("vrf-table auto")
        sut.config.render_full_config()
        sut.device.sudo("nv config apply startup -y")
        # sut.device.sudo('net add vrf %s vrf-table auto' % self.vrf)
        # sut.device.sudo('net commit')
        sut.device.sudo("sed -i '/iface vlan1/ a \    vrf mgmt' /etc/network/interfaces")
        sut.device.sudo('ifreload -a -X eth0 -X mgmt')
        sut.device.sudo('ip rule add to %s/32 table %s' % (str(srv1_ifaces[0].ip.address[0].ip), self.vrf))

        # Verify the node is accessible when it needs to contact radius server via  vrf.
        verify_node_access(self, sut, self.radius_usr1, self.radius_usr1_pw)

    # @attr(tags=['nightly', 'radius'])
    @WithTopo._handle_errors
    def test_10_radius_accounting_records(self):

        """
        Name: radius_accounting_records
        ====

        Description:
        ============
           Verify accounting records are sent to radius accounting server

        Steps:
        ============
         1. Log onto node using local and radius users
         2. Verify accounting records exist for radius users
         3. Verify accounting records do not exist for local user
         4. Repeat for second server

        Result:
        =======
        Mark the test as failed if any of the above steps are not satisfied.
        """
        sut = self.topo.switch
        srv1 = self.topo.host1
        srv2 = self.topo.host2

        srv1_ifaces = list(srv1.config.get_swp_interfaces().values())
        srv2_ifaces = list(srv2.config.get_swp_interfaces().values())

        # Start with second server down
        srv2.device.sudo('ip link set %s down' % srv2_ifaces[0].name)

        # remove log on srv1 (if it exists)
        srv1.device.sudo('rm -rf /var/log/freeradius/radacct', warn_only=True)

        sleep(1)

        start_tcpdump(srv1)
        verify_node_access(self, sut, self.local_usr, self.local_usr_pw)
        verify_node_access(self, sut, self.radius_adm1, self.radius_adm1_pw)
        verify_node_access(self, sut, self.radius_usr1, self.radius_usr1_pw)

        check_tcpdump(srv1)

        out = srv1.device.sudo('cat /var/log/freeradius/radacct/%s/*' % sut.vlan_ip, warn_only=True)
        if (re.search('.*"%s".*Start.*"%s".*Stop' % (self.local_usr, self.local_usr), out, re.DOTALL) == None):
            log.info("Success: Did not find accounting records for local user %s on srv1" % (self.local_usr))
        else:
            log.error("Failed: Found unexpected accounting records for %s on srv1" % (self.local_usr))
            assert False, 'Failed: Found unexpected accounting records for %s on srv1' % (self.local_usr)

        if (re.search('.*"%s".*Start.*"%s".*Stop' % (self.radius_adm1, self.radius_adm1), out, re.DOTALL) == None):
            # if (re.search('.*"%s".*Start.*' % (self.radius_adm1), out, re.DOTALL == None)):
            log.error("Failed: Did not find expected accounting records for %s on srv1" % (self.radius_adm1))
            assert False, 'Failed: Did not find expected accounting records for %s on srv1' % (self.radius_adm1)
        else:
            log.info("Success: Found expected accounting records for %s on srv1" % (self.radius_adm1))

        if (re.search('.*"%s".*Start.*"%s".*Stop' % (self.radius_usr1, self.radius_usr1), out, re.DOTALL) == None):
            # if (re.search('.*"%s".*Start.*'% (self.radius_usr1), out, re.DOTALL) == None):
            log.error("Failed: Did not find expected accounting records for %s on srv1" % (self.radius_usr1))
            assert False, 'Failed: Did not find expected accounting records for %s on srv1' % (self.radius_usr1)
        else:
            log.info("Success: Found expected accounting records for %s on srv1" % (self.radius_usr1))

        # Bring up second server
        srv2.device.sudo('ip link set %s up' % srv2_ifaces[0].name)
        sleep(2)

        # remove log on srv2 (if it exists)
        srv2.device.sudo('rm -rf /var/log/freeradius/radacct', warn_only=True)

        # Keep first down for this test
        srv1.device.sudo('ip link set %s down' % srv1_ifaces[0].name)

        sleep(1)

        start_tcpdump(srv2)

        verify_node_access(self, sut, self.local_usr, self.local_usr_pw)
        verify_node_access(self, sut, self.radius_adm1, self.radius_adm1_pw)
        verify_node_access(self, sut, self.radius_usr1, self.radius_usr1_pw)
        verify_node_access(self, sut, self.radius_usr2, self.radius_usr2_pw)
        verify_node_access(self, sut, self.radius_usr3, self.radius_usr3_pw)

        check_tcpdump(srv2)

        out = srv2.device.sudo('cat /var/log/freeradius/radacct/%s/*' % sut.vlan_ipv6, warn_only=True)
        if (re.search('.*"%s".*Start.*"%s".*Stop' % (self.local_usr, self.local_usr), out, re.DOTALL) == None):
            log.info("Success: Did not find accounting records for local user %s on srv2" % (self.local_usr))
        else:
            log.error("Failed: Found unexpected accounting records for %s on srv2" % (self.local_usr))
            assert False, 'Failed: Found unexpected accounting records for %s on srv2' % (self.local_usr)

        if (re.search('.*"%s".*Start.*"%s".*Stop' % (self.radius_adm1, self.radius_adm1), out, re.DOTALL) == None):
            # if (re.search('.*"%s".*Start.*' % (self.radius_adm1), out, re.DOTALL == None)):
            log.error("Failed: Did not find expected accounting records for %s on srv2" % (self.radius_adm1))
            assert False, 'Failed: Did not find expected accounting records for %s on srv2' % (self.radius_adm1)
        else:
            log.info("Success: Found expected accounting records for %s on srv2" % (self.radius_adm1))

        if (re.search('.*"%s".*Start.*"%s".*Stop' % (self.radius_usr1, self.radius_usr1), out, re.DOTALL) == None):
            # if (re.search('.*"%s".*Start.*' % (self.radius_usr1), out, re.DOTALL == None)):
            log.error("Failed: Did not find expected accounting records for %s on srv2" % (self.radius_usr1))
            assert False, 'Failed: Did not find expected accounting records for %s on srv2' % (self.radius_usr1)
        else:
            log.info("Success: Found expected accounting records for %s on srv2" % (self.radius_usr1))

        if (re.search('.*"%s".*Start.*"%s".*Stop' % (self.radius_usr2, self.radius_usr2), out, re.DOTALL) == None):
            log.error("Failed: Did not find expected accounting records for %s on srv2" % (self.radius_usr2))
            assert False, 'Failed: Did not find expected accounting records for %s on srv2' % (self.radius_usr2)
        else:
            log.info("Success: Found expected accounting records for %s on srv2" % (self.radius_usr2))

        if (re.search('.*"%s".*Start.*"%s".*Stop' % (self.radius_usr3, self.radius_usr3), out, re.DOTALL) == None):
            log.error("Failed: Did not find expected accounting records for %s on srv2" % (self.radius_usr3))
            assert False, 'Failed: Did not find expected accounting records for %s on srv2' % (self.radiusl_usr3)
        else:
            log.info("Success: Found expected accounting records for %s on srv2" % (self.radius_usr3))

        login_cumulus(self, sut)

    # @attr(tags=['smoke', 'nightly', 'radius', 'fw-smoke'])
    @WithTopo._handle_errors
    def test_11_radius_priv_default(self):

        """
        Name: radius_priv_default
        ====

        Description:
        ============
           Verify default priv-lvl 15 user can execute priv commands
           Verify priv-lvl < default 15 cannot execute priv commands

        Steps:
        ============
         1. Verify priv-lvl 15 use can execute sudo commands
         2. Verify priv-lvl < 15 cannot execute sudo commands
         3. Verify priv-lvl 15 use can execute priv commands
         4. Verify priv-lvl < 15 cannot execute priv commands
         5. Verify priv-lvl 15 use can execute priv commands as sudo
         6. Verify priv-lvl < 15 cannot execute priv commands as sudo
         7. Verify expected user directorys were created

        Result:
        =======
        Mark the test as failed if any of the above steps are not satisfied.
        """
        sut = self.topo.switch
        srv1 = self.topo.host1
        srv2 = self.topo.host2

        # Verify priv lvl 15 is able to execute sudo level commands.
        verify_sudo_access(self, sut, ("%s15" % self.radius_priv), ("%s15" % self.radius_priv_pw))

        # Verify priv lvl 0 thru 14 is not able to execute sudo level commands.
        for i in range(0, 15):
            verify_sudo_denied(self, sut, ("%s%s" % (self.radius_priv, str(i))),
                               ("%s%s" % (self.radius_priv_pw, str(i))))

        # Verify priv lvl 15 is able to execute priv level commands.
        verify_priv_access(self, sut, ("%s15" % self.radius_priv), ("%s15" % self.radius_priv_pw))

        # Verify priv lvl 0 thru 14 is not able to execute priv level commands.
        for i in range(0, 15):
            verify_priv_denied(self, sut, ("%s%s" % (self.radius_priv, str(i))),
                               ("%s%s" % (self.radius_priv_pw, str(i))))

        # Verify priv lvl 15 is able to execute priv level commands.
        verify_priv_sudo_access(self, sut, ("%s15" % self.radius_priv), ("%s15" % self.radius_priv_pw))

        # Verify priv lvl 0 thru 14 is not able to execute priv sudo level commands.
        for i in range(0, 15):
            verify_priv_sudo_denied(self, sut, ("%s%s" % (self.radius_priv, str(i))),
                                    ("%s%s" % (self.radius_priv_pw, str(i))))

        login_cumulus(self, sut)

        # Verify expected directories exist.
        for i in range(0, 16):
            check_directory_exists(sut, ("%s%s" % (self.radius_priv, str(i))))

    @attr(tags=['nightly', 'radius'])
    @WithTopo._handle_errors
    def test_12_radius_priv_lvl_change(self):

        """
        Name: radius_priv_lvl_change
        ====

        Description:
        ============
           Verify priv-lvl can be changed from default of 15

        Steps:
        ============
         1. Change priv-lvl to 1
         2. Verify priv-lvl 0 cannot execute sudo commands
         3. Verify priv-lvl > 1 can execute sudo commands
         4. Verify priv-lvl 0 cannot execute priv commands
         5. Verify priv-lvl > 1 can execute priv commands
         6. Verify priv-lvl 0 cannot execute priv commands as sudo
         7. Verify priv-lvl > 1 can execute priv commands as sudo
         8. Change priv-lvl to 8
         9. Verify priv-lvl 0 thru 7 cannot execute sudo commands
         10  Verify priv-lvl 8 thru 15 can execute sudo commands
         11. Verify priv-lvl 0 thru 7 cannot execute priv commands
         12. Verify priv-lvl 8 thru 15 can execute priv commands
         13. Verify priv-lvl 0 thru 7 cannot execute priv commands as sudo
         14. Verify priv-lvl 8 thru 15 can execute priv commands as sudo
         15 .Verify expected user directorys were created

        Result:
        =======
        Mark the test as failed if any of the above steps are not satisfied.
        """
        sut = self.topo.switch
        srv1 = self.topo.host1
        srv2 = self.topo.host2

        sut.device.sudo("echo 'priv-lvl 1' >> /etc/pam_radius_auth.conf")

        # Verify priv lvl 0 is not able to execute sudo level commands.
        verify_sudo_denied(self, sut, ("%s0" % self.radius_priv), ("%s0" % self.radius_priv_pw))

        # Verify priv lvl 1 thru 15 is able to execute sudo level commands.
        for i in range(1, 16):
            verify_sudo_access(self, sut, ("%s%s" % (self.radius_priv, str(i))),
                               ("%s%s" % (self.radius_priv_pw, str(i))))

        # Verify priv lvl 0 is not able to execute priv level commands.
        verify_priv_denied(self, sut, ("%s0" % self.radius_priv), ("%s0" % self.radius_priv_pw))

        # Verify priv lvl 1 thru 15 is able to execute priv level commands.
        for i in range(1, 16):
            verify_priv_access(self, sut, ("%s%s" % (self.radius_priv, str(i))),
                               ("%s%s" % (self.radius_priv_pw, str(i))))

        # Verify priv lvl 0 is not able to execute priv sudo level commands.
        verify_priv_sudo_denied(self, sut, ("%s0" % self.radius_priv), ("%s0" % self.radius_priv_pw))

        # Verify priv lvl 1 thru 15 is able to execute priv sudo level commands.
        for i in range(1, 16):
            verify_priv_sudo_access(self, sut, ("%s%s" % (self.radius_priv, str(i))),
                                    ("%s%s" % (self.radius_priv_pw, str(i))))

        login_cumulus(self, sut)

        # remove existing connections
        for i in range(0, 16):
            username = "%s%s" % (self.radius_priv, str(i))
            try:
                if sut.hard_target:
                    #     x =  connections.get('%s@%s:22' % (username, sut.hard_target.hostname))
                    #     x.close()
                    #     del connections['%s@%s:22' % (username, sut.hard_target.hostname)]
                    # else:
                    #     del connections['%s@localhost:%s' % (username, ssh_port1)]
                    c = Connection('%s@%s:22' % (username, sut.hard_target.hostname))
                    if c is not None:
                        c.close()
            except Exception as e:
                log.debug("%s connection does not exist" % username)
            else:
                log.info("removed connection for %s" % username)

        sut.device.sudo("sed -i 's/%s/%s/g'  /etc/pam_radius_auth.conf" % ('priv-lvl 1', 'priv-lvl 8'))

        # Verify priv lvl 0 thru 7 are not able to execute sudo level commands.
        for i in range(4, 5):
            verify_sudo_denied(self, sut, ("%s%s" % (self.radius_priv, str(i))),
                               ("%s%s" % (self.radius_priv_pw, str(i))))

        # Verify priv lvl 8 thru 15 are able to execute sudo level commands.
        for i in range(14, 15):
            verify_sudo_access(self, sut, ("%s%s" % (self.radius_priv, str(i))),
                               ("%s%s" % (self.radius_priv_pw, str(i))))

        # Verify priv lvl 0 thru 7 are not able to execute priv level commands.
        for i in range(4, 5):
            verify_priv_denied(self, sut, ("%s%s" % (self.radius_priv, str(i))),
                               ("%s%s" % (self.radius_priv_pw, str(i))))

        # Verify priv lvl 8 thru 15 are able to execute priv level commands.
        for i in range(14, 15):
            verify_priv_access(self, sut, ("%s%s" % (self.radius_priv, str(i))),
                               ("%s%s" % (self.radius_priv_pw, str(i))))

        # Verify priv lvl 0 thru 7 are not able to execute priv sudo level commands.
        for i in range(4, 5):
            verify_priv_sudo_denied(self, sut, ("%s%s" % (self.radius_priv, str(i))),
                                    ("%s%s" % (self.radius_priv_pw, str(i))))

        # Verify priv lvl 8 thru 15 are able to execute priv sudo level commands.
        for i in range(14, 15):
            verify_priv_sudo_access(self, sut, ("%s%s" % (self.radius_priv, str(i))),
                                    ("%s%s" % (self.radius_priv_pw, str(i))))

        login_cumulus(self, sut)

        # Verify expected directories exist.
        for i in range(4, 5):
            check_directory_exists(sut, ("%s%s" % (self.radius_priv, str(i))))

    @attr(tags=['nightly', 'radius'])
    @WithTopo._handle_errors
    def test_13_radius_priv_mapped_priv_user(self):

        """
        Name: radius_priv_mapped_priv_user
        ====

        Description:
        ============
           Verify mapped_priv_user can be changed

        Steps:
        ============
         1. Change priv-lvl to 8
         2. Change radius_priv_user to cumulus_priv_user in
                  /etc/pam_radius_auth.conf and
                  /etc/nss_mapusre.conf
         3. Create a new user "cumulus_priv_user" using useradd command
         4. Modify /etc/group to add cumulus_priv_user sudo and netedit groups
         5. Remove radius_priv_user using userdel command
         6. Verify priv-lvl 0 thru 7 cannot execute sudo commands
         7. Verify priv-lvl 8 thru 15 can execute sudo commands
         8. Verify priv-lvl 0 thru 7 cannot execute priv commands
         9. Verify priv-lvl 8 thru 15 can execute priv commands
         10. Verify priv-lvl 0 thru 7 cannot execute priv commands as sudo
         11. Verify priv-lvl 8 thru 15 can execute priv commands as sudo
         12. Verify expected user directories were created

        Result:
        =======
        Mark the test as failed if any of the above steps are not satisfied.
        """
        sut = self.topo.switch
        srv1 = self.topo.host1
        srv2 = self.topo.host2

        sut.device.sudo("echo 'priv-lvl 8' >> /etc/pam_radius_auth.conf")
        sut.device.sudo("sed -i 's/%s/%s/g' /etc/pam_radius_auth.conf" % ('radius_priv_user', 'cumulus_priv_user'))
        sut.device.sudo("sed -i 's/%s/%s/g' /etc/nss_mapuser.conf" % ('radius_priv_user', 'cumulus_priv_user'))

        sut.device.sudo(
            'useradd cumulus_priv_user -g radius_users -s /sbin/radius_shell -d /home/cumulus_priv_user -c "radius privileged user,,,"')
        sut.device.sudo("sed -i 's/%s/%s/g' /etc/group" % ('radius_priv_user', 'cumulus_priv_user'))
        sut.device.sudo('userdel radius_priv_user')

        # Verify priv lvl 0 thru 7 are not able to execute sudo level commands.
        for i in range(0, 8):
            verify_sudo_denied(self, sut, ("%s%s" % (self.radius_priv, str(i))),
                               ("%s%s" % (self.radius_priv_pw, str(i))))

        # Verify priv lvl 8 thru 15 are able to execute sudo level commands.
        for i in range(8, 16):
            verify_sudo_access(self, sut, ("%s%s" % (self.radius_priv, str(i))),
                               ("%s%s" % (self.radius_priv_pw, str(i))))

        # Verify priv lvl 0 thru 8 are not able to execute priv level commands.
        for i in range(0, 8):
            verify_priv_denied(self, sut, ("%s%s" % (self.radius_priv, str(i))),
                               ("%s%s" % (self.radius_priv_pw, str(i))))

        # Verify priv lvl 8 thru 15 are able to execute priv level commands.
        for i in range(8, 16):
            verify_priv_access(self, sut, ("%s%s" % (self.radius_priv, str(i))),
                               ("%s%s" % (self.radius_priv_pw, str(i))))

        # Verify priv lvl 0 thru 8 are not able to execute priv sudo level commands.
        for i in range(0, 8):
            verify_priv_sudo_denied(self, sut, ("%s%s" % (self.radius_priv, str(i))),
                                    ("%s%s" % (self.radius_priv_pw, str(i))))

        # Verify priv lvl 8 thru 15 are able to execute priv sudo level commands.
        for i in range(8, 16):
            verify_priv_sudo_access(self, sut, ("%s%s" % (self.radius_priv, str(i))),
                                    ("%s%s" % (self.radius_priv_pw, str(i))))

        login_cumulus(self, sut)

        # Verify expected directories exist.
        for i in range(0, 16):
            check_directory_exists(sut, ("%s%s" % (self.radius_priv, str(i))))


def check_directory_exists(node, dirname):
    try:
        node.device.sudo("ls /home/%s" % dirname)
    except:
        log.info("Failed: Expected directory %s does not exist" % dirname)
        assert False, "Failed: Expected directory %s does not exist" % dirname
    log.info("Success: Expected directory %s exists" % dirname)
    return


def verify_node_access(self, node, username, password):
    ssh_port1 = 22
    if node.hard_target:
        sw_ob = NetworkDevice(node.hard_target.hostname, user=username, password=password)
    else:
        ssh_port1 = self.topo.ssh_port(node)
        sw_ob = NetworkDevice('localhost', port=ssh_port1, user=username, password=password)

    log.info('Attempt to access %s using username=%s password=%s' % (node.name, username, password))

    try:

        out = sw_ob.run('hostname')
        if out:
            result = True
            if node.hard_target:
                c = Connection('%s@%s:22' % (username, node.hard_target.hostname))
                if c is not None:
                    c.close()

    except Exception:
        log.error('Failed: %s is not accessible with username=%s password=%s' % (node.name, username, password))
        login_cumulus(self, node)
        assert False, 'Failed: %s is not accessible with username=%s password=%s' % (node.name, username, password)
    else:
        log.info('Success: %s is accessible with username=%s password=%s' % (node.name, username, password))


def verify_node_denied(self, node, username, password):
    ssh_port1 = 22
    if node.hard_target:
        sw_ob = NetworkDevice(node.hard_target.hostname, user=username, password=password)
    else:
        ssh_port1 = self.topo.ssh_port(node)
        sw_ob = NetworkDevice('localhost', port=ssh_port1, user=username, password=password)

    log.info('Attempt to access %s using username=%s password=%s' % (node.name, username, password))
    # with settings(abort_on_prompts=True):
    try:
        out = sw_ob.run('hostname')
        if out:
            if node.hard_target:
                c = Connection('%s@%s:22' % (username, node.hard_target.hostname))
                if c is not None:
                    c.close()

    except Exception:
        log.info('Success: %s is not accessible with username=%s password=%s' % (node.name, username, password))
    else:
        log.error('Failed: %s is accessible with username=%s password=%s' % (node.name, username, password))
        login_cumulus(self, node)
        assert False, 'Failed: %s is accessible with username=%s password=%s' % (node.name, username, password)


def verify_sudo_access(self, node, username, password):
    ssh_port1 = 22
    if node.hard_target:
        sw_ob = NetworkDevice(node.hard_target.hostname, user=username, password=password)
    else:
        ssh_port1 = self.topo.ssh_port(node)
        sw_ob = NetworkDevice('localhost', port=ssh_port1, user=username, password=password)

    log.info('Attempt sudo access %s using username=%s password=%s' % (node.name, username, password))

    try:

        out = sw_ob.sudo('lldpctl', warn_only=True)
        if out:
            if node.hard_target:
                c = Connection('%s@%s:22' % (username, node.hard_target.hostname))
                if c is not None:
                    c.close()
    except Exception:
        log.error('Failed: %s is not accessible with username=%s password=%s' % (node.name, username, password))
        login_cumulus(self, node)
        assert False, 'Failed: %s is not accessible with username=%s password=%s' % (node.name, username, password)
    else:
        if 'neighbors:' in out:
            log.info('Success: user %s has sudo access' % username)
        elif 'not allowed' in out:
            log.error('Failed: user %s was denied sudo access' % username)
            login_cumulus(self, node)
            assert False, 'Failed: user %s was denied sudo access' % username
        else:
            log.error('Failed: unexpected output for user %s' % username)
            login_cumulus(self, node)
            assert False, 'Failed: unexpected output for user %s' % username

        log.info('Success: %s is accessible with username=%s password=%s' % (node.name, username, password))


def verify_sudo_denied(self, node, username, password):
    ssh_port1 = 22
    if node.hard_target:
        sw_ob = NetworkDevice(node.hard_target.hostname, user=username, password=password)
    else:
        ssh_port1 = self.topo.ssh_port(node)
        sw_ob = NetworkDevice('localhost', port=ssh_port1, user=username, password=password)

    log.info('Attempt sudo access failure %s using username=%s password=%s' % (node.name, username, password))

    try:
        out = sw_ob.sudo('lldpctl', warn_only=True)

        if out:
            if node.hard_target:
                c = Connection('%s@%s:22' % (username, node.hard_target.hostname))
                if c is not None:
                    c.close()
    except Exception:
        log.error('Failed: %s is not accessible with username=%s password=%s' % (node.name, username, password))
        login_cumulus(self, node)
        assert False, 'Failed: %s is not accessible with username=%s password=%s' % (node.name, username, password)
    else:
        if 'not allowed' in out or out == '':
            log.info('Success: user %s does not have sudo access' % username)
        elif 'neighbors:' in out:
            log.error('Failed: user %s has unexpected sudo access' % username)
            login_cumulus(self, node)
            assert False, 'user %s has unexpected sudo access' % username
        else:
            log.error('Failed: unexpected output for user %s' % username)
            login_cumulus(self, node)
            assert False, 'Failed: unexpected output for user %s' % username


def verify_priv_access(self, node, username, password):
    ssh_port1 = 22
    if node.hard_target:
        sw_ob = NetworkDevice(node.hard_target.hostname, user=username, password=password)
    else:
        ssh_port1 = self.topo.ssh_port(node)
        sw_ob = NetworkDevice('localhost', port=ssh_port1, user=username, password=password)

    log.info('Attempt priv access %s using username=%s password=%s' % (node.name, username, password))

    try:
        out = sw_ob.run('net add hostname dummy', warn_only=True)
        if out:
            if node.hard_target:
                c = Connection('%s@%s:22' % (username, node.hard_target.hostname))
                if c is not None:
                    c.close()
    except Exception:
        log.error('Failed: %s is not accessible with username=%s password=%s' % (node.name, username, password))
        login_cumulus(self, node)
        assert False, 'Failed: %s is not accessible with username=%s password=%s' % (node.name, username, password)
    else:
        if 'ERROR' in out:
            log.error('Failed: user %s was denied net add priv access' % username)
            login_cumulus(self, node)
            assert False, 'Failed: user %s was denied net add priv access' % username
        else:
            log.info('Success: user %s has net add priv access' % username)

    try:
        out = sw_ob.run('net del hostname', warn_only=True)
        if out:
            if node.hard_target:
                c = Connection('%s@%s:22' % (username, node.hard_target.hostname))
                if c is not None:
                    c.close()
    except Exception:
        log.error('Failed: %s is not accessible with username=%s password=%s' % (node.name, username, password))
        login_cumulus(self, node)
        assert False, 'Failed: %s is not accessible with username=%s password=%s' % (node.name, username, password)
    else:
        if 'ERROR' in out:
            log.error('Failed: user %s was denied net del priv access' % username)
            login_cumulus(self, node)
            assert False, 'Failed: user %s was denied net del priv access' % username
        else:
            log.info('Success: user %s has net del priv access' % username)

    # with settings(abort_on_prompts=True):
    # try:
    #     out = sw_ob.run('net abort', warn_only=True)
    #     if out:
    #         if node.hard_target:
    #             x =  connections.get('%s@%s:22' % (username, node.hard_target.hostname))
    #             x.close()
    #             del connections['%s@%s:22' % (username, node.hard_target.hostname)]
    #         else:
    #             del connections['%s@localhost:%s' % (username, ssh_port1)]
    # except Exception:
    #     log.error('Failed: %s is not accessible with username=%s password=%s' % (node.name, username, password))
    #     login_cumulus(self, node)
    #     assert False, 'Failed: %s is not accessible with username=%s password=%s' % (node.name, username, password)
    # else:
    #     if 'ERROR' in out:
    #         log.error('Failed: user %s was denied net abort priv access' % username)
    #         login_cumulus(self, node)
    #         assert False, 'Failed: user %s was denied net abort priv access' % username
    #     else:
    #        log.info('Success: user %s has net abort priv access' % username)


def verify_priv_denied(self, node, username, password):
    ssh_port1 = 22
    if node.hard_target:
        sw_ob = NetworkDevice(node.hard_target.hostname, user=username, password=password)
    else:
        ssh_port1 = self.topo.ssh_port(node)
        sw_ob = NetworkDevice('localhost', port=ssh_port1, user=username, password=password)

    log.info('Attempt priv access failure %s using username=%s password=%s' % (node.name, username, password))

    try:
        # out = sw_ob.run('net add hostname dummy', warn_only=True)
        out = sw_ob.run('hostname dummy', warn_only=True)
        if out:
            if node.hard_target:
                c = Connection('%s@%s:22' % (username, node.hard_target.hostname))
                if c is not None:
                    c.close()
    except Exception:
        log.error('Failed: %s is not accessible with username=%s password=%s' % (node.name, username, password))
        login_cumulus(self, node)
        assert False, 'Failed: %s is not accessible with username=%s password=%s' % (node.name, username, password)
    else:
        if 'ERROR' in out or out == "":
            log.info('Success: user %s does not have net add priv access' % username)
        else:
            log.error('Failed: unexpected output for user %s' % username)
            login_cumulus(self, node)
            assert False, 'Failed: unexpected output for user %s' % username


def verify_priv_sudo_access(self, node, username, password):
    ssh_port1 = 22
    if node.hard_target:
        sw_ob = NetworkDevice(node.hard_target.hostname, user=username, password=password)
    else:
        ssh_port1 = self.topo.ssh_port(node)
        sw_ob = NetworkDevice('localhost', port=ssh_port1, user=username, password=password)

    log.info('Attempt priv sudo access %s using username=%s password=%s' % (node.name, username, password))

    try:
        out = sw_ob.sudo('net commit', warn_only=True)
        if out:
            if node.hard_target:
                c = Connection('%s@%s:22' % (username, node.hard_target.hostname))
                if c is not None:
                    c.close()
    except Exception:
        log.error('Failed: %s is not accessible with username=%s password=%s' % (node.name, username, password))
        login_cumulus(self, node)
        assert False, 'Failed: %s is not accessible with username=%s password=%s' % (node.name, username, password)
    else:
        if 'ERROR' in out:
            log.error('Failed: user %s was denied sudo net commit priv access' % username)
            login_cumulus(self, node)
            assert False, 'Failed: user %s was denied sudo net commit priv access' % username
        else:
            log.info('Success: user %s has sudo net commit priv access' % username)

    try:
        out = sw_ob.sudo('net add hostname dummy', warn_only=True)
        if out:
            if node.hard_target:
                c = Connection('%s@%s:22' % (username, node.hard_target.hostname))
                if c is not None:
                    c.close()
    except Exception:
        log.error('Failed: %s is not accessible with username=%s password=%s' % (node.name, username, password))
        login_cumulus(self, node)
        assert False, 'Failed: %s is not accessible with username=%s password=%s' % (node.name, username, password)
    else:
        if 'ERROR' in out:
            log.error('Failed: user %s was denied sudo net add priv access' % username)
            login_cumulus(self, node)
            assert False, 'Failed: user %s was denied sudo net add priv access' % username
        else:
            log.info('Success: user %s has sudo net add priv access' % username)

    try:
        out = sw_ob.sudo('net del hostname', warn_only=True)
        if out:
            if node.hard_target:
                c = Connection('%s@%s:22' % (username, node.hard_target.hostname))
                if c is not None:
                    c.close()
    except Exception:
        log.error('Failed: %s is not accessible with username=%s password=%s' % (node.name, username, password))
        login_cumulus(self, node)
        assert False, 'Failed: %s is not accessible with username=%s password=%s' % (node.name, username, password)
    else:
        if 'ERROR' in out:
            log.error('Failed: user %s was denied sudo net del priv access' % username)
            login_cumulus(self, node)
            assert False, 'Failed: user %s was denied sudo net del priv access' % username
        else:
            log.info('Success: user %s has sudo net del priv access' % username)

    try:
        out = sw_ob.sudo('net abort', warn_only=True)
        if out:
            if node.hard_target:
                c = Connection('%s@%s:22' % (username, node.hard_target.hostname))
                if c is not None:
                    c.close()

    except Exception:
        log.error('Failed: %s is not accessible with username=%s password=%s' % (node.name, username, password))
        login_cumulus(self, node)
        assert False, 'Failed: %s is not accessible with username=%s password=%s' % (node.name, username, password)
    else:
        if 'ERROR' in out:
            log.error('Failed: user %s was denied net abort priv access' % username)
            login_cumulus(self, node)
            assert False, 'Failed: user %s was denied net abort priv access' % username
        else:
            log.info('Success: user %s has net abort priv access' % username)


def verify_priv_sudo_denied(self, node, username, password):
    ssh_port1 = 22
    if node.hard_target:
        sw_ob = NetworkDevice(node.hard_target.hostname, user=username, password=password)
    else:
        ssh_port1 = self.topo.ssh_port(node)
        sw_ob = NetworkDevice('localhost', port=ssh_port1, user=username, password=password)

    log.info('Attempt priv sudo access failure %s using username=%s password=%s' % (node.name, username, password))

    try:
        out = sw_ob.sudo('hostname dummy', warn_only=True)
        if out:
            if node.hard_target:
                c = Connection('%s@%s:22' % (username, node.hard_target.hostname))
                if c is not None:
                    c.close()

    except Exception:
        log.error('Failed: %s is not accessible with username=%s password=%s' % (node.name, username, password))
        login_cumulus(self, node)
        assert False, 'Failed: %s is not accessible with username=%s password=%s' % (node.name, username, password)
    else:
        if 'not allowed' in out or out == '':
            log.info('Success: user %s does not have net add sudo priv access' % username)
        else:
            log.error('Failed: unexpected output for user %s' % username)
            login_cumulus(self, node)
            assert False, 'Failed: unexpected output for user %s' % username


def start_tcpdump(node, iface="swp1"):
    node.device.sudo_bg("tcpdump -i %s -n -U -w capture.txt 2> capture.log" % iface)


def stop_tcpdump(node):
    sleep(5)  # need to wait for tcpdump to catch up
    node.device.sudo("killall tcpdump", warn_only=True)


def check_tcpdump(node, warn_only=False):
    stop_tcpdump(node)
    out = node.device.sudo('tcpdump -n -r capture.txt 2> /dev/null')
    log.debug(out)
