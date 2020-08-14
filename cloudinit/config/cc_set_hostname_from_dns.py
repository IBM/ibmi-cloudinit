# =================================================================
# Licensed Materials - Property of IBM
#
# (c) Copyright IBM Corp. 2015 All Rights Reserved
#
# US Government Users Restricted Rights - Use, duplication or
# disclosure restricted by GSA ADP Schedule Contract with IBM Corp.
# =================================================================

from cloudinit.settings import PER_INSTANCE
from cloudinit import util
from cloudinit import netinfo
import socket


frequency = PER_INSTANCE


def handle(name, _cfg, _cloud, log, _args):
    default_interface = 'eth0'
    system_info = util.system_info()
    if 'aix' in system_info['platform'].lower():
        default_interface = 'en0'

    interface = util.get_cfg_option_str(_cfg,
                                        'set_hostname_from_interface',
                                        default=default_interface)
    log.debug('Setting hostname based on interface %s' % interface)
    full_hostname = None
    ipv4addr = None
    ipv6addr = None
    # Look up the IP address on the interface
    # and then reverse lookup the hostname in DNS
    info = netinfo.netdev_info()
    if interface in info:
        if 'addr' in info[interface]:
            ipv4addr = info[interface]['addr']
        if 'addr6' in info[interface]:
            ipv6addr = info[interface]['addr6'].split('/')[0]
    else:
        log.warning('Interface %s was not found on the system. '
                    'Interfaces found on system: %s' % (interface,
                                                        info.keys()))
    ipaddr = ipv4addr or ipv6addr
    try:
        full_hostname, alias, iplist = socket.gethostbyaddr(ipaddr)
        if full_hostname:
            log.debug('Setting hostname on VM as %s' % full_hostname)
            short_hostname = full_hostname.split('.')[0]
            _cloud.distro.set_hostname(short_hostname, fqdn=full_hostname)
    except socket.error:
        log.warning('No hostname found for IP addresses %s' % ipaddr)
