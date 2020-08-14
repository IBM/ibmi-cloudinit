# vi: ts=4 expandtab
#
#    Copyright (C) 2013 Hewlett-Packard Development Company, L.P.
#
#    Author: Juerg Haefliger <juerg.haefliger@hp.com>
#
#    Leaning very heavily on the RHEL and Debian implementation
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 3, as
#    published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

from cloudinit import distros

from cloudinit.distros.parsers.hostname import HostnameConf

from cloudinit import helpers
from cloudinit import log as logging
from cloudinit import util

from cloudinit.distros import net_util
from cloudinit.distros import rhel_util
from cloudinit.settings import PER_INSTANCE

LOG = logging.getLogger(__name__)


class Distro(distros.Distro):
    clock_conf_fn = '/etc/sysconfig/clock'
    locale_conf_fn = '/etc/sysconfig/language'
    network_conf_fn = '/etc/sysconfig/network'
    hostname_conf_fn = '/etc/HOSTNAME'
    network_script_tpl = '/etc/sysconfig/network/ifcfg-%s'
    network_script_dir = '/etc/sysconfig/network'
    resolve_conf_fn = '/etc/resolv.conf'
    routes_fn = '/etc/sysconfig/network/routes'
    net_rules_fn = '/etc/udev/rules.d/70-persistent-net.rules'
    net_rules_entry_tpl = 'SUBSYSTEM=="net", ATTR{address}=="%s", NAME="%s"'
    tz_local_fn = '/etc/localtime'

    def __init__(self, name, cfg, paths):
        distros.Distro.__init__(self, name, cfg, paths)
        # This will be used to restrict certain
        # calls from repeatly happening (when they
        # should only happen say once per instance...)
        self._runner = helpers.Runners(paths)
        self.osfamily = 'suse'

    def install_packages(self, pkglist):
        self.package_command('install', args='-l', pkgs=pkglist)

    # override distros.Distro method to allow setting up persistence
    def apply_network(self, settings, bring_up=True):
        # Write it out
        dev_names, mac_addrs = self._write_network(settings)

        # Now try to bring them up
        if bring_up:
            self._bring_down_interfaces(dev_names)
            self._set_up_persistence(dev_names, mac_addrs)
            return self._bring_up_interfaces(dev_names)
        return False    

    def _set_up_persistence(self, dev_names, mac_addrs):
        # generate the persistence file
        net_rules = ''
        for dev_name, mac_addr in zip(dev_names, mac_addrs):
            if dev_name != 'lo':
                net_rules += '\n'
                net_rules += self.net_rules_entry_tpl % (mac_addr, dev_name)
        util.write_file(self.net_rules_fn, net_rules, mode=0o644)
        
        # reload udev rules to make interfaces have correct names
        util.subp(['udevadm control --reload-rules && udevadm trigger'],
                  shell=True)

    def _write_network(self, settings):
        # Convert debian settings to ifcfg format
        entries = net_util.translate_network(settings)
        LOG.debug("Translated ubuntu style network settings %s into %s",
                  settings, entries)

        # Match Debian/Ubunto distro functionality of clean slating
        # the network interface configuration.
        # Remove all existing ifcfg-eth* files.  This cleans up files that
        # are left around if you capture an image from a VM with 5 NICs
        # and deploy it with 1 NIC.
        rhel_util.remove_ifcfg_files(self.network_script_dir)
        rhel_util.remove_resolve_conf_file(self.resolve_conf_fn)
        util.del_file(self.routes_fn)

        # Make the intermediate format as the suse format...
        nameservers = []
        searchservers = []
        dev_names = entries.keys()
        mac_addrs = []
        for (dev, info) in entries.iteritems():
            mac_addrs.append(info.get('hwaddress'))
            net_fn = self.network_script_tpl % (dev)
            mode = info.get('auto')
            if mode:
                mode = 'auto'
            else:
                mode = 'manual'
            net_cfg = {}
            net_cfg['BOOTPROTO'] = info.get('bootproto')
            net_cfg['BROADCAST'] = info.get('broadcast')
            net_cfg['LLADDR'] = info.get('hwaddress')
            net_cfg['STARTMODE'] = mode
            if info['ipv6']:
                prefix = info.get('netmask')
                ipv6addr = info.get('address')
                net_cfg['IPADDR_0'] = ipv6addr
                net_cfg['PREFIXLEN_0'] = prefix
                net_cfg['LABEL_0'] = '0'
            if info['ipv4']:
                net_cfg['NETMASK'] = info.get('netmask')
                net_cfg['IPADDR'] = info.get('address')
            if dev != 'lo':
                # net_cfg['ETHERDEVICE'] = dev
                net_cfg['ETHTOOL_OPTIONS'] = ''
                net_cfg['USERCONTROL'] = 'no'
                net_cfg['NM_CONTROLLED'] = 'no'
                net_cfg['BRIDGE'] = 'yes'
            else:
                net_cfg['FIREWALL'] = 'no'
            if dev == 'eth0' and info.get('gateway'):
                self._write_default_route(self.routes_fn, info.get('gateway'))

            # Remove the existing cfg file so the network configuration
            # is a replacement versus an update to match debian distro
            # functionality.
            if dev != 'lo':
                util.del_file(net_fn)
            rhel_util.update_sysconfig_file(net_fn, net_cfg, True)
            if 'dns-nameservers' in info:
                nameservers.extend(info['dns-nameservers'])
            if 'dns-search' in info:
                searchservers.extend(info['dns-search'])
        if nameservers or searchservers:
            rhel_util.update_resolve_conf_file(self.resolve_conf_fn,
                                               nameservers, searchservers)
        return dev_names, mac_addrs

    def _write_default_route(self, routesfile, gateway):
        content = 'default %s - -\n' % gateway
        util.write_file(routesfile, content, 0o644)

    def apply_locale(self, locale, out_fn=None):
        if not out_fn:
            out_fn = self.locale_conf_fn
        locale_cfg = {
            'RC_LANG': locale,
        }
        rhel_util.update_sysconfig_file(out_fn, locale_cfg)

    def _write_hostname(self, hostname, out_fn):
        conf = None
        try:
            # Try to update the previous one
            # so lets see if we can read it first.
            conf = self._read_hostname_conf(out_fn)
        except IOError:
            pass
        if not conf:
            conf = HostnameConf('')
        conf.set_hostname(hostname)
        util.write_file(out_fn, str(conf), 0o644)

    def _select_hostname(self, hostname, fqdn):
        # Prefer the short hostname over the long
        # fully qualified domain name
        if not hostname:
            return fqdn
        return hostname

    def _read_system_hostname(self):
        host_fn = self.hostname_conf_fn
        return (host_fn, self._read_hostname(host_fn))

    def _read_hostname_conf(self, filename):
        conf = HostnameConf(util.load_file(filename))
        conf.parse()
        return conf

    def _read_hostname(self, filename, default=None):
        hostname = None
        try:
            conf = self._read_hostname_conf(filename)
            hostname = conf.hostname
        except IOError:
            pass
        if not hostname:
            return default
        return hostname

    def _bring_up_interfaces(self, device_names):
        if device_names and 'all' in device_names:
            raise RuntimeError(('Distro %s can not translate '
                                'the device name "all"') % (self.name))
        return distros.Distro._bring_up_interfaces(self, device_names)

    def set_timezone(self, tz):
        tz_file = self._find_tz_file(tz)
        # Adjust the sysconfig clock zone setting
        clock_cfg = {
            'TIMEZONE': str(tz),
        }
        rhel_util.update_sysconfig_file(self.clock_conf_fn, clock_cfg)
        # This ensures that the correct tz will be used for the system
        util.copy(tz_file, self.tz_local_fn)

    def package_command(self, command, args=None, pkgs=None):
        if pkgs is None:
            pkgs = []

        cmd = ['zypper']
        # No user interaction possible, enable non-interactive mode
        cmd.append('--non-interactive')

        # Comand is the operation, such as install
        cmd.append(command)

        # args are the arguments to the command, not global options
        if args and isinstance(args, str):
            cmd.append(args)
        elif args and isinstance(args, list):
            cmd.extend(args)

        pkglist = util.expand_package_list('%s-%s', pkgs)
        cmd.extend(pkglist)

        # Allow the output of this to flow outwards (ie not be captured)
        util.subp(cmd, capture=False)

    def update_package_sources(self):
        self._runner.run("update-sources", self.package_command,
                         ['refresh'], freq=PER_INSTANCE)
