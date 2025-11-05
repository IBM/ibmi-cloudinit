import re
import time
import datetime
import os
import os.path
import pwd
import sys

from cloudinit import distros
from cloudinit import helpers
from cloudinit import log as logging
from cloudinit import util
from cloudinit import ssh_util

from cloudinit.distros import net_util
from cloudinit.distros import IBMi_util
from cloudinit.settings import PER_INSTANCE

from itoolkit import iToolKit
from itoolkit import iCmd
from itoolkit import iPgm
from itoolkit import iSrvPgm
from itoolkit import iData
from itoolkit import iDS
from itoolkit.transport import DatabaseTransport
from itoolkit.transport import DirectTransport

__ibmi_distro_version__ = "1.9"

# Initialize DirectTransport 
itransport = DirectTransport()

basestring = str
LOG = logging.getLogger(__name__)


class Distro(distros.Distro):
    hostname_conf_fn = "/etc/hosts"
    resolve_conf_fn = "/etc/resolv.conf"

    def __init__(self, name, cfg, paths):
        distros.Distro.__init__(self, name, cfg, paths)
        # This will be used to restrict certain
        # calls from repeatly happening (when they
        # should only happen say once per instance...)
        self._runner = helpers.Runners(paths)
        self.osfamily = 'IBMi'

    def install_packages(self, pkglist):
        self.package_command('install', pkgs=pkglist)

    def insert_ssh_pubkey(self, pub_keys, sys_cfg):
        pub_ssh_keys = set()
        for key in pub_keys.keys():
            pub_ssh_keys.add(pub_keys[key])

        (users, _groups) = distros.normalize_users_groups(sys_cfg, self)

        (user, _user_config) = distros.extract_default(users)
        LOG.debug("Default user is %s", str(user))
        if user:
            LOG.debug("Inserting ssh public keys for user %s", user)
            ssh_util.setup_user_keys(pub_ssh_keys, user)
        else:
            LOG.error(
                "There is no default user to insert the ssh authorized keys")

    def apply_network(self, settings, bring_up=True):
        '''IBMi platform does not implement this'''
        return False

    def _get_rscname_of_ethernet(self):
        itool = iToolKit()
        itool.add(
            iSrvPgm('qgyrhr', 'QGYRHR', 'QgyRtvHdwRscList')
            .addParm(iDS('RHRL0100_t', {'len': 'rhrlen'})
                     .addData(iData('rhrRet', '10i0', ''))
                     .addData(iData('rhrAvl', '10i0', ''))
                     .addData(iData('rhrNbr', '10i0', '', {'enddo': 'mycnt'}))
                     .addData(iData('rhrLen', '10i0', ''))
                     .addData(iDS('res_t', {'dim': '999', 'dou': 'mycnt'})
                              .addData(iData('resCat', '10i0', ''))
                              .addData(iData('resLvl', '10i0', ''))
                              .addData(iData('resLin', '10i0', ''))
                              .addData(iData('resNam', '10a', ''))
                              .addData(iData('resTyp', '4a', ''))
                              .addData(iData('resMod', '3a', ''))
                              .addData(iData('resSts', '1a', ''))
                              .addData(iData('resSys', '8a', ''))
                              .addData(iData('resAdp', '12a', ''))
                              .addData(iData('resDsc', '50h', ''))
                              .addData(iData('resKnd', '24b', ''))
                              )
                     )
            .addParm(iData('rcvlen', '10i0', '', {'setlen': 'rhrlen'}))
            .addParm(iData('fmtnam', '10a', 'RHRL0100'))
            .addParm(iData('rescat', '10i0', '2'))
            .addParm(iDS('ERRC0100_t', {'len': 'errlen'})
                     .addData(iData('errRet', '10i0', ''))
                     .addData(iData('errAvl', '10i0', ''))
                     .addData(iData('errExp', '7A', '', {'setlen': 'errlen'}))
                     .addData(iData('errRsv', '1A', ''))
                     )
        )

        itool.call(itransport)
        qgyrhr = itool.dict_out('qgyrhr')

        mac_resource_names = dict()
        if 'success' in qgyrhr:
            LOG.debug(qgyrhr['success'])
            LOG.debug("    Length of receiver variable......%s",
                      qgyrhr['rcvlen'])
            LOG.debug("    Format name......................%s",
                      qgyrhr['fmtnam'])
            LOG.debug("    Resource category................%s",
                      qgyrhr['rescat'])
            RHRL0100_t = qgyrhr['RHRL0100_t']
            LOG.debug("    RHRL0100_t:")
            LOG.debug("      Number of resources returned...%s",
                      RHRL0100_t['rhrNbr'])
            if int(RHRL0100_t['rhrNbr']) > 0:
                res_t = RHRL0100_t['res_t']
                # mac_resource_names will be the mapping of mac address and resource name for assigning ip address
                for rec in res_t:
                    LOG.debug(
                        "        --------------------------------------------------------")
                    LOG.debug(
                        "        Resource name................%s", rec['resNam'])
                    if rec['resKnd'] == "0000000000000008000000000000000400000800000004":
                        LOG.debug(
                            "        Description..................%s", rec['resDsc'])
                        LOG.debug(
                            "        Resource kind................%s", rec['resKnd'])
                        mac_address = self._get_ethernet_mac(rec['resNam'])
                        if mac_address:
                            LOG.debug(
                                "Found Enthernet Port resource %s which has MAC address %s", rec['resNam'], mac_address)
                            mac_resource_names[mac_address] = rec['resNam']
        else:
            LOG.debug("Error when calling QgyRtvHdwRscList to list communication resources and their MAC address, error=%s", qgyrhr['error'])
        return mac_resource_names

    def _get_ethernet_mac(self, res_name):
        itool = iToolKit()
        itool.add(
            iSrvPgm('qgyrhr', 'QGYRHR', 'QgyRtvHdwRscInfo', {'error': 'on'})
            .addParm(iDS('RHRI0100_t', {'len': 'rhrlen'})
                     .addData(iData('rhrRet', '10i0', ''))
                     .addData(iData('rhrAvl', '10i0', ''))
                     .addData(iData('sysBusNum', '10i0', ''))
                     .addData(iData('sysBdNum', '10i0', ''))
                     .addData(iData('sysCdNum', '10i0', ''))
                     .addData(iData('IOBusAdd', '10i0', ''))
                     .addData(iData('AdaptAdd', '10i0', ''))
                     .addData(iData('PortNum', '10i0', ''))
                     .addData(iData('srNum', '10a', ''))
                     .addData(iData('partNum', '12a', ''))
                     .addData(iData('frmID', '4a', ''))
                     .addData(iData('cdPst', '5a', ''))
                     .addData(iData('locCd', '79a', ''))
                     .addData(iData('expSrNum', '15a', ''))
                     .addData(iData('LANSpeed', '8a', '', {'hex': 'on'}))
                     .addData(iData('LinkAgg', '1a', '', {'hex': 'on'}))
                     .addData(iData('MAC', '6a', '', {'hex': 'on'}))
                     )
            .addParm(iData('rcvlen', '10i0', '', {'setlen': 'rhrlen'}))
            .addParm(iData('fmtnam', '8a', 'RHRI0100'))
            .addParm(iData('resnam', '10a', res_name))
            .addParm(
                iDS('ERRC0100_t', {'len': 'errlen'})
                .addData(iData('errRet', '10i0', ''))
                .addData(iData('errAvl', '10i0', ''))
                .addData(iData('errExp', '7A', '', {'setlen': 'errlen'}))
                .addData(iData('errRsv', '1A', ''))
            )
        )

        itool.call(itransport)
        qgyrhr = itool.dict_out('qgyrhr')

        mac = None
        if 'success' in qgyrhr:
            LOG.debug(qgyrhr['success'])
            LOG.debug("    Format name......................%s",
                      qgyrhr['fmtnam'])
            LOG.debug("    Resource Name....................%s", qgyrhr['resnam'])
            RHRI0100_t = qgyrhr['RHRI0100_t']
            LOG.debug("    RHRI0100_t:")
            if int(RHRI0100_t['rhrAvl']) > 0:
                mac = RHRI0100_t['MAC']
                LOG.debug("        Mac address................%s", mac)
                mac.ljust(12, '0')
                LOG.debug("        Mac address append 0.......%s", mac)
        else:
            LOG.debug("Error when calling QgyRtvHdwRscInfo to retrieve MAC address, error=%s", qgyrhr['error'])
        return mac

    def apply_IBMi_network(self, settings, fqdn, bring_up=True):
        entries = net_util.translate_network(settings)

        mac_rscnames = self._get_rscname_of_ethernet()
        if (not mac_rscnames) or (len(mac_rscnames) < 1):
            LOG.error(
                "No Virtual Ethernet Port hardware resource found")
            return False
        LOG.debug("mac_rscnames=%s", str(mac_rscnames))

        if fqdn and fqdn.find(".") > 0:
            toks = str(fqdn).split(".")
            hostname = toks[0]
        else:
            hostname = fqdn
        LOG.debug("hostname=%s", hostname)

        mac_lind = self._create_line_description(mac_rscnames)
        LOG.debug(
            "mac_lind=%s", str(mac_lind))
        self._write_IBMi_network(entries, hostname, mac_lind)
        return True

    def _write_network(self, settings):
        '''IBMi platform does not implement this'''
        return False

    def apply_locale(self, locale, out_fn=None):
        util.subp(['/usr/bin/chlang', '-M', str(locale)])

    def retrieve_mac_from_lind(self, lind):
        '''Un-used function'''
        itool = iToolKit()
        itool.add(
            iPgm('qdcrlind', 'QDCRLIND')
            .addParm(iDS('LIND0500_t', {'len': 'rhrlen'})
                     .addData(iData('aa1', '10i0', ''))
                     .addData(iData('aa2', '10i0', ''))
                     .addData(iData('aa3', '10i0', ''))
                     .addData(iData('bb', '96h', ''))
                     .addData(iData('a1', '10i0', ''))
                     .addData(iData('a2', '10i0', ''))
                     .addData(iData('a3', '10i0', ''))
                     .addData(iData('a4', '10i0', ''))
                     .addData(iData('a5', '10i0', ''))
                     .addData(iData('a6', '10i0', ''))
                     .addData(iData('a7', '10i0', ''))
                     .addData(iData('a8', '10i0', ''))
                     .addData(iData('a9', '10i0', ''))
                     .addData(iData('a10', '10i0', ''))
                     .addData(iData('a11', '10i0', ''))
                     .addData(iData('a12', '10i0', ''))
                     .addData(iData('numasc', '10i0', '', {'enddo': 'myasc'}))
                     .addData(iData('b1', '10i0', ''))
                     .addData(iData('b2', '10i0', ''))
                     .addData(iData('numssap', '10i0', '', {'enddo': 'myssap'}))
                     .addData(iData('c', '20i0', ''))
                     .addData(iData('numgad', '10i0', '', {'enddo': 'mygad'}))
                     .addData(iData('d', '10i0', ''))
                     .addData(iData('e', '20h', ''))
                     .addData(iData('mac', '12a', ''))
                     .addData(iData('f', '60h', ''))
                     .addData(iData('g', '10i0', ''))
                     .addData(iData('h', '40h', ''))
                     .addData(iData('i', '10i0', ''))
                     .addData(iData('j', '12h', ''))
                     .addData(iData('k', '60i0', ''))
                     .addData(iData('numpvc', '10i0', '', {'enddo': 'mypvc'}))
                     .addData(iData('l', '10i0', ''))
                     .addData(iData('m', '220h', ''))
                     .addData(iData('n', '20i0', ''))
                     .addData(iData('o', '52h', ''))
                     .addData(iData('p', '20i0', ''))
                     .addData(iData('q', '32h', ''))
                     .addData(iData('r', '10i0', ''))
                     .addData(iData('numser', '10i0', '', {'enddo': 'myser'}))
                     .addData(iData('s', '20h', ''))
                     .addData(iData('t', '10i0', ''))
                     .addData(iData('numagg', '10i0', '', {'enddo': 'myagg'}))
                     .addData(iData('u', '10i0', ''))
                     .addData(iData('s', '12h', ''))
                     .addData(iDS('asc_t', {'dim': '999', 'dou': 'myasc'})
                              .addData(iData('ASCName', '10h', ''))
                              .addData(iData('reserved1', '2h', ''))
                              )
                     .addData(iDS('ssap_t', {'dim': '999', 'dou': 'myssap'})
                              .addData(iData('maxframe', '10i0', ''))
                              .addData(iData('ssapadd', '10h', ''))
                              .addData(iData('ssaptype', '10h', ''))
                              )
                     .addData(iDS('gad_t', {'dim': '999', 'dou': 'mygad'})
                              .addData(iData('egda', '12h', ''))
                              )
                     .addData(iDS('ssap_t', {'dim': '999', 'dou': 'mypvc'})
                              .addData(iData('pvc', '10i0', ''))
                              )
                     .addData(iDS('ser_t', {'dim': '999', 'dou': 'myser'})
                              .addData(iData('serr', '12h', ''))
                              )
                     .addData(iDS('ssap_t', {'dim': '999', 'dou': 'myagg'})
                              .addData(iData('aggname', '10h', ''))
                              .addData(iData('aggre', '2h', ''))
                              .addData(iData('aggsta', '10i0', ''))
                              )
                     )
            .addParm(iData('rcvlen', '10i0', '', {'setlen': 'rhrlen'}))
            .addParm(iData('fmtnam', '8a', 'LIND0500'))
            .addParm(iData('rescat', '10a', lind))
            .addParm(
                iDS('ERRC0100_t', {'len': 'errlen'})
                .addData(iData('errRet', '10i0', ''))
                .addData(iData('errAvl', '10i0', ''))
                .addData(iData('errExp', '7A', '', {'setlen': 'errlen'}))
                .addData(iData('errRsv', '1A', ''))
            )
        )

        itool.call(itransport)
        qdcrlind = itool.dict_out('qdcrlind')

        if 'success' in qdcrlind:
            LOG.debug(qdcrlind['success'])
            LOG.debug("The line description %s has the MAC %s",
                      lind, qdcrlind['LIND0500_t']['mac'])
            return qdcrlind['LIND0500_t']['mac'].strip()
        else:
            LOG.error(
                "Failed to retrieve MAC address from the line description %s", lind)
            return None

    def _create_line_description(self, mac_res):
        mac_lind = dict()
        index_lind = 0
        for mac in mac_res.keys():
            rscname = 'RSRCNAME(' + mac_res[mac] + ')'
            lind = "CLOUDINIT" + str(index_lind)
            line_description = 'LIND(' + lind + ')'
            index_lind = index_lind + 1
            crt_lined_cmd = ['system']
            log_crt_lined_cmd = ['system']
            crt_lined_cmd.extend(['CRTLINETH', line_description, rscname])
            log_crt_lined_cmd.extend(['CRTLINETH', line_description, rscname])
            try:
                LOG.debug(
                    "Execute command %s", log_crt_lined_cmd)
                util.subp(crt_lined_cmd, logstring=log_crt_lined_cmd)
            except Exception as e:
                LOG.error("Failed to execute command %s with error %s",
                          log_crt_lined_cmd, e)
                raise e
            vary_config_cmd = ['system']
            log_vary_config_cmd = ['system']
            vary_config_cmd.extend(
                ['VRYCFG', 'CFGOBJ(' + lind + ') CFGTYPE(*LIN) STATUS(*ON)'])
            log_vary_config_cmd.extend(
                ['VRYCFG', 'CFGOBJ(' + lind + ') CFGTYPE(*LIN) STATUS(*ON)'])
            try:
                LOG.debug(
                    "Execute command %s", log_vary_config_cmd)
                util.subp(vary_config_cmd, logstring=log_vary_config_cmd)
            except Exception as e:
                LOG.error("Failed to execute command %s with error %s",
                          log_vary_config_cmd, e)
            mac_lind[mac] = lind
        return mac_lind

    def _write_IBMi_network(self, entries, hostname, mac_lind):
        dev_names = sorted(entries)
        LOG.debug("Sorted dev_names=%s", dev_names)
        create_dhcp_file = True
        gateway = "NOTSET"
        gateway_list = {}
        nameservers = []
        searchsvrs = []
        for dev in dev_names:
            info = entries[dev]
            rmc_ethernet = False
            run_cmd = 0
            chdev_cmd = ['system']
            log_chdev_cmd = ['system']
            ipv4address = ''
            if dev not in 'lo':
                aix_dev = IBMi_util.translate_devname(dev)
                LOG.debug(
                    "dev=%s, info=%s, aix_dev=%s", dev_names, info, aix_dev)
                if info.get('bootproto') == 'dhcp':
                    IBMi_util.config_dhcp(aix_dev, info, create_dhcp_file)
                    create_dhcp_file = False
                else:
                    chdev_cmd.append('ADDTCPIFC')
                    log_chdev_cmd.append('ADDTCPIFC')
                    if info['ipv6'] or info['ipv4']:
                        run_cmd = 1
                    chdev_opts = {
                        "address": 'INTNETADR(ipaddress)',
                        "netmask": 'SUBNETMASK(mask)',
                        "gateway": 'NEXTHOP(gateway)',
                    }
                    for (key, val) in info.items():
                        LOG.debug(
                            "key=%s, val=%s in info.iteritem", key, val)
                        if key in chdev_opts and val and isinstance(val, basestring):
                            if key in 'address':
                                val = "\'" + val + "\'"
                                ipv4address = val
                                chdev_cmd.append(
                                    chdev_opts[key].replace('ipaddress', val))
                                log_chdev_cmd.append(
                                    chdev_opts[key].replace('ipaddress', val))
                            if key in 'netmask':
                                val = "\'" + val + "\'"
                                chdev_cmd.append(
                                    chdev_opts[key].replace('mask', val))
                                log_chdev_cmd.append(
                                    chdev_opts[key].replace('mask', val))
                            if key in 'gateway':
                                gateway = "\'" + val + "\'"
                    if info['ipv6'] and gateway == "NOTSET":
                        rmc_ethernet = True
                    # get the line description name from the MAC address
                    mac_address = info['hwaddress'].upper().replace(":", "")
                    lined = mac_lind[mac_address]
                    chdev_cmd.append("LIND(" + lined + ")")
                    log_chdev_cmd.append("LIND(" + lined + ")")
                    if run_cmd:
                        try:
                            LOG.debug(
                                "Execute command %s", log_chdev_cmd)
                            util.subp(chdev_cmd, logstring=log_chdev_cmd)
                        except Exception as e:
                            LOG.error(
                                "Failed to execute command %s with error %s", log_chdev_cmd, e)
                    # execute ADDTCPRTE cmd if this is a normal tcp ethernet
                    if (not rmc_ethernet) and (gateway != "NOTSET") and (gateway not in gateway_list.keys()):
                        gateway_list[gateway] = True
                        add_tcp_rt_cmd = ['system']
                        log_add_tcp_rte_cmd = ['system']
                        next_hop_option = "NEXTHOP(" + gateway + ")"
                        if info['ipv4']:
                            add_tcp_rt_cmd.extend(
                                ['ADDTCPRTE', "RTEDEST(*DFTROUTE)", next_hop_option, "MTU(*IFC)"])
                            log_add_tcp_rte_cmd.extend(
                                ['ADDTCPRTE', "RTEDEST(*DFTROUTE)", next_hop_option, "MTU(*IFC)"])
                        if info['ipv6']: # ipv4 and ipv6 can not both as True
                            add_tcp_rt_cmd.extend(
                                ['ADDTCPRTE', "RTEDEST(*DFT6ROUTE)", next_hop_option, "BINDLIND(" + lined + ") ADRPFXLEN(*NONE)"])
                            log_add_tcp_rte_cmd.extend(
                                ['ADDTCPRTE', "RTEDEST(*DFT6ROUTE)", next_hop_option, "BINDLIND(" + lined + ") ADRPFXLEN(*NONE)"])
                        try:
                            LOG.debug(
                                "Execute command %s", log_add_tcp_rte_cmd)
                            util.subp(add_tcp_rt_cmd,
                                      logstring=log_add_tcp_rte_cmd)
                        except Exception as e:
                            LOG.error(
                                "Failed to execute command %s with error %s", log_add_tcp_rte_cmd, e)

                    if 'dns-nameservers' in info:
                        for dns_ns in info['dns-nameservers']:
                            if dns_ns not in nameservers:
                                nameservers.append(dns_ns)
                        LOG.debug(
                            "dns-nameservers=%s", info['dns-nameservers'])
                    if 'dns-search' in info:
                        searchsvrs.extend(info['dns-search'])
                        LOG.debug(
                            "searchservers=%s", info['dns-search'])

                    if not rmc_ethernet:
                        chg_hosttable_cmd = ['system']
                        log_chg_hosttable_cmd = ['system']
                        # e.g. ADDTCPHTE INTNETADR('x.x.x.x') HOSTNAME(ETHERNETHOST) TEXT('ETHERNETHOST on Ethernet subnet')
                        address_option = 'INTNETADR(' + ipv4address + ')'
                        fullhostname = "\'" + hostname + "\'"
                        if 'dns-search' in info:
                            for s in info['dns-search']:
                                fullhostname = fullhostname + " " + "\'" + hostname + '.' + s + "\'"
                        fullhostname = fullhostname.strip().upper()
                        hostname_option = 'HOSTNAME(' + fullhostname + ')'
                        chg_hosttable_cmd.extend(
                            ['ADDTCPHTE', address_option, hostname_option])
                        log_chg_hosttable_cmd.extend(
                            ['ADDTCPHTE', address_option, hostname_option])

                        try:
                            LOG.debug(
                                "Execute command %s", log_chg_hosttable_cmd)
                            util.subp(chg_hosttable_cmd,
                                      logstring=log_chg_hosttable_cmd)
                        except Exception as e:
                            LOG.error(
                                "Failed to execute command %s with error %s", log_chg_hosttable_cmd, e)

        chg_tcp_domain_cmd = ['system']
        log_chg_tcp_domain_cmd = ['system']
        host_option = "HOSTNAME(samplehost)"
        domain_option = "DMNNAME(sampledomain)"
        search_option = "DMNSCHLIST(samplesearchlist)"
        dns_options = "INTNETADR(sampledns)"

        searchservers = ""
        if searchsvrs:
            searchsvrset = set(searchsvrs)
            for s in searchsvrset:
                searchservers = s + " " + searchservers
                searchservers = searchservers.strip()
                searchservers = "\'" + searchservers + "\'"

        dns_s = ["*NONE", "*NONE", "*NONE"]
        dnsservers = ""
        if nameservers:
            for index in range(min(len(nameservers), 3)):
                dns_s[index] = nameservers[index]
            for s in dns_s:
                if s == "*NONE":
                    dnsservers = dnsservers + ' ' + s
                else:
                    dnsservers = dnsservers + ' ' + "\'" + s + "\'"
        else:
            dnsservers = "*NONE *NONE *NONE"
        dnsservers = dnsservers.strip()
        dns_options = dns_options.replace('sampledns', dnsservers).upper()
        search_option = search_option.replace(
            'samplesearchlist', searchservers).upper()
        host_option = host_option.replace(
            'samplehost', "\'" + hostname + "\'").upper()
        domain_option = domain_option.replace(
            'sampledomain', searchservers).upper()
        chg_tcp_domain_cmd.extend(
            ['CHGTCPDMN', host_option, domain_option, search_option, dns_options])
        log_chg_tcp_domain_cmd.extend(
            ['CHGTCPDMN', host_option, domain_option, search_option, dns_options])

        try:
            LOG.debug(
                "Execute command %s", log_chg_tcp_domain_cmd)
            util.subp(chg_tcp_domain_cmd, logstring=log_chg_tcp_domain_cmd)
        except Exception as e:
            LOG.error("Failed to execute command %s with error %s",
                      log_chg_tcp_domain_cmd, e)

        strtcp_set = True

        itool = iToolKit()
        itool.add(
            iPgm('qwcripla', 'QWCRIPLA')
            .addParm(
                iDS('IPLA0100_t', {'len': 'rhrlen'})
                .addData(iData('aaa', '10i0', ''))
                .addData(iData('bbb', '10i0', ''))
                .addData(iData('cccc', '1a', ''))
                .addData(iData('dddd', '1a', ''))
                .addData(iData('eee', '1a', ''))
                .addData(iData('fff', '1a', ''))
                .addData(iData('ggg', '1a', ''))
                .addData(iData('hhh', '1a', ''))
                .addData(iData('iii', '1a', ''))
                .addData(iData('jjj', '1a', ''))
                .addData(iData('kkk', '1a', ''))
                .addData(iData('lll', '1a', ''))
                .addData(iData('mmm', '1a', ''))
                .addData(iData('nnn', '1a', ''))
                .addData(iData('ooo', '1a', ''))
                .addData(iData('starttcp', '1a', ''))
                .addData(iData('qqq', '1a', ''))
            )
            .addParm(iData('rcvlen', '10i0', '', {'setlen': 'rhrlen'}))
            .addParm(iData('fmtipl', '10a', 'IPLA0100'))
            .addParm(
                iDS('ERRC0100_t', {'len': 'errlen'})
                .addData(iData('errRet', '10i0', ''))
                .addData(iData('errAvl', '10i0', ''))
                .addData(iData('errExp', '7A', '', {'setlen': 'errlen'}))
                .addData(iData('errRsv', '1A', ''))
            )
        )
        # xmlservice
        itool.call(itransport)
        # output
        qwcripla = itool.dict_out('qwcripla')
        if 'success' in qwcripla:
            IPLA0100_t = qwcripla['IPLA0100_t']
            LOG.debug("The STRTCP setting in IPL attributes is: %s", IPLA0100_t['starttcp'])
            if IPLA0100_t['starttcp'] == '0':
                strtcp_set = False
        else:
            LOG.debug(
                "Failed to get the STRTCP from IPL attribute, will do STRTCP by default")

        if strtcp_set == True:
            LOG.debug("About to start the TCP......")
            start_tcp_cmd = ['system']
            log_start_tcp_cmd = ['system']
            start_tcp_cmd.append("STRTCP")
            log_start_tcp_cmd.append("STRTCP")
            try:
                LOG.debug(
                    "Execute command %s", log_start_tcp_cmd)
                util.subp(start_tcp_cmd, logstring=log_start_tcp_cmd)
            except Exception as e:
                LOG.error("Failed to execute command %s with error %s",
                          log_start_tcp_cmd, e)
        else:
            LOG.debug("Not to start the TCP......")

        return dev_names

    def _write_hostname(self, hostname, out_fn):
        # Permanently change the hostname for inet0 device in the ODM
        util.subp(['/usr/sbin/chdev', '-l', 'inet0',
                   '-a', 'hostname=' + str(hostname)])
        shortname = hostname.split('.')[0]
        # Change the node for the uname process
        util.subp(['/usr/bin/uname', '-S', str(shortname)[0:32]])

    def _select_hostname(self, hostname, fqdn):
        # Prefer the short hostname over the long
        # fully qualified domain name
        if not hostname:
            return fqdn
        return hostname

    def _read_system_hostname(self):
        host_fn = self.hostname_conf_fn
        return (host_fn, self._read_hostname(host_fn))

    def _read_hostname(self, filename, default=None):
        (out, _err) = util.subp(['/usr/bin/hostname'])
        if len(out):
            return out
        else:
            return default

    def _bring_up_interface(self, device_name):
        if device_name in 'lo':
            return True

        cmd = ['/usr/sbin/chdev', '-l',
               IBMi_util.translate_devname(device_name), '-a', 'state=up']
        LOG.debug(
            "Attempting to run bring up interface %s using command %s", device_name, cmd)
        try:
            (_out, err) = util.subp(cmd)
            if len(err):
                LOG.warn("Running %s resulted in stderr output: %s", cmd, err)
            return True
        except util.ProcessExecutionError:
            util.logexc(LOG, "Running interface command %s failed", cmd)
            return False

    def _bring_up_interfaces(self, device_names):
        if device_names and 'all' in device_names:
            raise RuntimeError(
                ('Distro %s can not translate the device name "all"') % (self.name))
        for d in device_names:
            if not self._bring_up_interface(d):
                return False
        return True

    def _bring_down_interface(self, device_name):
        if device_name in 'lo':
            return True

        cmd = ['/usr/sbin/chdev', '-l',
               IBMi_util.translate_devname(device_name), '-a', 'state=down']
        LOG.debug(
            "Attempting to run bring down interface %s using command %s", device_name, cmd)
        try:
            (_out, err) = util.subp(cmd)
            if len(err):
                LOG.warn("Running %s resulted in stderr output: %s", cmd, err)
            return True
        except util.ProcessExecutionError:
            util.logexc(LOG, "Running interface command %s failed", cmd)
            return False

    def _bring_down_interfaces(self, device_names):
        if device_names and 'all' in device_names:
            raise RuntimeError(
                ('Distro %s can not translate the device name "all"') % (self.name))
        am_failed = 0
        for d in device_names:
            if not self._bring_down_interface(d):
                am_failed += 1
        if am_failed == 0:
            return True
        return False

    def set_timezone(self, tz):
        cmd = ['/usr/bin/chtz', tz]
        util.subp(cmd)

    def package_command(self, command, args=None, pkgs=None):
        if not pkgs:
            pkgs = []

        cmd = ['yum']
        # If enabled, then yum will be tolerant of errors on the command line
        # with regard to packages.
        # For example: if you request to install foo, bar and baz and baz is
        # installed; yum won't error out complaining that baz is already
        # installed.
        cmd.append("-t")
        # Determines whether or not yum prompts for confirmation
        # of critical actions. We don't want to prompt...
        cmd.append("-y")

        if args and isinstance(args, str):
            cmd.append(args)
        elif args and isinstance(args, list):
            cmd.extend(args)

        cmd.append(command)

        pkglist = util.expand_package_list('%s-%s', pkgs)
        cmd.extend(pkglist)

        # Allow the output of this to flow outwards (ie not be captured)
        util.subp(cmd, capture=False)

    def update_package_sources(self):
        self._runner.run("update-sources", self.package_command,
                         ["makecache"], freq=PER_INSTANCE)

    def retrieve_job_dateformat(self):
        itool = iToolKit(iparm=0, iret=0, ids=1, irow=0)
        itool.add(iCmd('rtvjoba', 'RTVJOBA DATFMT(?)'))
        # xmlservice
        itool.call(itransport)
        # output
        rtvjoba = itool.dict_out('rtvjoba')

        if 'error' in rtvjoba:
            LOG.info("Failed to get the job default date format, error=%s",
                     str(rtvjoba['error']))
            return ""
        else:
            LOG.info(
                "Successfully get the job default date format=%s", rtvjoba['DATFMT'])
            return rtvjoba['DATFMT']

    def create_group(self, name, members):
        group_add_cmd = ["system", "CRTUSRPRF", name,
                         "PASSWORD(*NONE)", "STATUS(*DISABLED)"]

        # Check if group exists, and then add it doesn't
        if self.is_user_exist(name):
            LOG.warn("Skipping creation of existing group %s", name)
        else:
            try:
                util.subp(group_add_cmd)
                LOG.info("Created new group %s", name)
            except Exception:
                LOG.error("Failed to create group %s", name)

        # Add members to the group, if so defined
        if len(members) > 0:
            for member in members:
                if not self.is_user_exist(member):
                    LOG.warn(
                        "Unable to add group member %s to group %s, user does not exist", member, name)
                    continue
                try:
                    add_group_cmd = self.formulate_addmem_group_cmd(
                        member, name)
                    if add_group_cmd:
                        util.subp(add_group_cmd)
                        LOG.info("Added user %s to group %s", member, name)
                except Exception:
                    LOG.error(
                        "Failed to add user %s to group %s", member, name)

    def users_account_info(self, username):
        pw_ent = pwd.getpwnam(username)
        if not pw_ent or not pw_ent.pw_dir:
            raise RuntimeError(
                "Unable to get account info for user %s", username)
        return pw_ent

    def create_homedir(self, user):
        pwent = self.users_account_info(user)
        homedir = pwent.pw_dir
        # set the home dir mode to 750? good?
        util.ensure_dir(homedir, mode=0o750)
        util.chownbyid(homedir, pwent.pw_uid, pwent.pw_gid)

    def add_user(self, name, existing, **kwargs):

        if not existing:
            adduser_cmd = ['system', 'CRTUSRPRF']
            log_adduser_cmd = ['system', 'CRTUSRPRF']
            if 'gecos' not in kwargs or not kwargs['gecos']:
                adduser_cmd.append(
                    "TEXT(\'USER PROFILE CREATED BY CLOUDINIT\')")
                log_adduser_cmd.append(
                    "TEXT(\'USER PROFILE CREATED BY CLOUDINIT\')")
        else:
            adduser_cmd = ['system', 'CHGUSRPRF']
            log_adduser_cmd = ['system', 'CHGUSRPRF']

        adduser_cmd.append("USRPRF(" + name + ")")
        log_adduser_cmd.append("USRPRF(" + name + ")")

        adduser_opts = {
            "homedir": "HOMEDIR(\'var\')",
            "gecos": "TEXT(\'var\')",
            "primary_group": 'GRPPRF(var)',
            "groups": 'SUPGRPPRF(var)',
            "expiredate": 'USREXPDATE(var)',
            "passwd": 'PASSWORD(var)',
            "plain_text_passwd": 'PASSWORD(var)',
            "home": "HOMEDIR(\'var\')",
        }

        date_format = {
            "*YMD": "%y%m%d",
            "*MDY": "%m%d%y",
            "*DMY": "%d%m%y",
            "*JUL": "%y%j",
        }

        empty_list = list()

        LOG.debug("==============user=============== %s", str(kwargs))

        hasOption = False

        for key, val in kwargs.items():
            if key in adduser_opts and val:
                hasOption = True
                if key == "homedir" and 'home' in kwargs and kwargs['home']:
                    continue
                if key == "passwd" and 'plain_text_passwd' in kwargs and kwargs['plain_text_passwd']:
                    continue
                if key == "expiredate":
                    try:
                        default_dfmt = self.retrieve_job_dateformat()
                        if default_dfmt == "":
                            continue
                        val = val.strftime(date_format[default_dfmt])
                    except Exception as e:
                        LOG.error(
                            "Failed to parse the expirate date %s with error %s, skip setting the expirate date", val, str(e))
                        continue
                if key == "primary_group":
                    if not self.is_user_exist(val):
                        if not kwargs.get('no_user_group', False):
                            self.create_group(val, empty_list)
                        else:
                            continue
                if key == "groups":
                    group_names = ""
                    for group in val.split(","):
                        if not self.is_user_exist(group):
                            if not kwargs.get('no_user_group', False):
                                self.create_group(group, empty_list)
                                group_names = group_names + " " + group.strip()
                        else:
                            group_names = group_names + " " + group.strip()
                    val = group_names.strip()
                    if (not val) or (val == ""):
                        continue

                adduser_cmd.extend([adduser_opts[key].replace('var', val)])

        # Do we need to care about no_create_home?
        if existing and not hasOption:
            return False

        # Run the command
        LOG.debug("Adding/changing user %s", name)
        try:
            util.subp(adduser_cmd, logstring=log_adduser_cmd)
            return True
        except Exception as e:
            util.logexc(LOG, "Failed to create user %s", name)
            raise e

    def set_passwd(self, user, passwd, hashed=False):
        cmd = ['system', 'CHGUSRPRF']

        cmd.append("USRPRF(" + user + ")")
        cmd.append("PASSWORD(" + passwd + ")")

        try:
            util.subp(cmd, logstring="change password for user " + user)
            LOG.debug("Executing cmd %s", cmd)
        except Exception as e:
            util.logexc(
                LOG, "Failed to set password for %s, error=%s", user, str(e))

        return True

    def is_user_exist(self, username):
        itool = iToolKit(iparm=0, iret=0, ids=1, irow=0)
        itool.add(
            iCmd('rtvusrprf', 'RTVUSRPRF USRPRF(' + username + ') RTNUSRPRF(?)'))
        # xmlservice
        itool.call(itransport)
        # output
        rtvusrprf = itool.dict_out('rtvusrprf')

        if 'error' in rtvusrprf:
            LOG.debug("user %s does not exist", username)
            return False
        else:
            LOG.debug("user %s does exist", username)
            return True

    def create_user(self, name, **kwargs):
        """
        Creates users for the system using the GNU passwd tools. This
        will work on an GNU system. This should be overriden on
        distros where useradd is not desirable or not available.
        """
        LOG.debug("Create user------------ %s", str(kwargs))

        try:
            user = name.replace("name:", "").strip()

            existing = self.is_user_exist(name)

            if not existing:
                LOG.info("user %s does not exist, start to create it", user)
                self.add_user(user, False, **kwargs)
            else:
                LOG.info(
                    "user %s already exists, change the user profiles", user)
                self.add_user(user, True, **kwargs)

            if 'homedir' in kwargs and kwargs['homedir']:
                if not os.path.isdir(kwargs['homedir']):
                    if not kwargs.get('no_create_home', False):
                        self.create_homedir(user)

            if 'home' in kwargs and kwargs['home']:
                if not os.path.isdir(kwargs['home']):
                    if not kwargs.get('no_create_home', False):
                        self.create_homedir(user)

            # the logic for lock_password and inactive are the same
            # for new user created, lock_password and inactive are default to true anyway
            # for existing user, if they define lock_password or inactive, set them to true
            if not existing and kwargs.get('lock_passwd', True):
                if ('passwd' in kwargs and kwargs['passwd']) or ('plain_text_passwd' in kwargs and kwargs['plain_text_passwd']):
                    LOG.info(
                        "user %s: because of defining the password, skipping lock password", user)
                else:
                    LOG.info("user %s: lock password", user)
                    self.lock_passwd(user)
            if existing and 'lock_passwd' in kwargs and kwargs.get('lock_passwd', True):
                # if ('passwd' in kwargs and kwargs['passwd']) or ('plain_text_passwd' in kwargs and kwargs['plain_text_passwd']):
                #    LOG.info("user %s: because of defining the password, skipping lock password...", user)
                # else:
                #    LOG.info("user %s: lock password...", user)
                #    self.lock_passwd(user)
                # Chang Le: lock_passwd has high priority
                LOG.info("user %s: lock password", user)
                self.lock_passwd(user)

            if not existing and kwargs.get('inactive', True):
                self.set_inactive(user)
            if existing and 'inactive' in kwargs and kwargs.get('inactive', True):
                self.set_inactive(user)
            # Chang Le: should be able to change the user to active when the inactive is False
            if existing and 'inactive' in kwargs and (not kwargs.get('inactive')):
                self.set_active(user)

            LOG.debug("keys are %s", str(kwargs.keys()))

            # Import SSH keys
            if 'ssh_authorized_keys' in kwargs:
                keys = set(kwargs['ssh_authorized_keys']) or []
                LOG.debug("key is %s, user is %s", str(keys), str(user))
                ssh_util.setup_user_keys(keys, user, options=None)

            return True
        except Exception as e:
            util.logexc(LOG, "Failed to add user %s, error=%s", user, str(e))
            return False

    def lock_passwd(self, name):
        """
        Lock the password of a user, i.e., disable password logins
        """
        try:
            # Need to use the short option name '-l' instead of '--lock'
            # (which would be more descriptive) since SLES 11 doesn't know
            # about long names.
            util.subp(['system', 'CHGUSRPRF', name, 'PASSWORD(*NONE)'])
        except Exception as e:
            util.logexc(
                LOG, "Failed to disable password for user %s, error=%s", name, str(e))

    def set_inactive(self, name):
        """
        set inactive of a user, i.e., disable the user
        """
        try:
            util.subp(['system', 'CHGUSRPRF', name, 'STATUS(*DISABLED)'])
        except Exception as e:
            util.logexc(
                LOG, "Failed to disable the user %s, error=%s", name, str(e))

    def set_active(self, name):
        """
        set active of a user, i.e., enable the user
        """
        try:
            util.subp(['system', 'CHGUSRPRF', name, 'STATUS(*ENABLED)'])
        except Exception as e:
            util.logexc(
                LOG, "Failed to enable the user %s, error=%s", name, str(e))

    def formulate_addmem_group_cmd(self, user, group):
        addmem_cmd = ['system', 'CHGUSRPRF', user]
        itool = iToolKit(iparm=0, iret=0, ids=1, irow=0)
        itool.add(iCmd('rtvusrprf', 'RTVUSRPRF USRPRF(' +
                       user + ') GRPPRF(?) SUPGRPPRF(?)'))
        # xmlservice
        itool.call(itransport)
        # output
        rtvusrprf = itool.dict_out('rtvusrprf')

        if 'error' in rtvusrprf:
            LOG.error("Failed to execute command: RTVUSRPRF USRPRF(%s) GRPPRF(?) SUPGRPPRF(?)", user)
        else:
            LOG.info("Retrieved user profile information of %s", user)
            LOG.info("GRPPRF is: %s", rtvusrprf['GRPPRF'])
            if rtvusrprf['GRPPRF'] == group.strip().upper():
                LOG.info(
                    "group %s is already the group of user %s, skip adding", group, user)
                return None
            if rtvusrprf['GRPPRF'] == "*NONE":
                addmem_cmd.append("GRPPRF(" + group + ")")
                return addmem_cmd

            users = ""
            LOG.info("SUPGRPPRF is: %s", rtvusrprf['SUPGRPPRF'])
            if rtvusrprf['SUPGRPPRF'] == "*NONE":
                users = group
            else:
                sub_userprf = rtvusrprf['SUPGRPPRF']
                num = len(sub_userprf)/10
                users = ""
                if num > 0:
                    LOG.info("there are %s SUPGRPPRF", str(num+1))
                    for index in range(num):
                        each_group = sub_userprf[(
                            index * 10): (index * 10 + 10)]
                        LOG.info("group is: %s", each_group)
                        if each_group.strip().upper() == group.strip().upper():
                            LOG.info(
                                "group %s is already the group of user %s, skip adding", group, user)
                            return None
                        else:
                            users = users + " " + each_group.strip()

                    index = index + 1
                    if len(sub_userprf) > (index * 10):
                        each_group = sub_userprf[(index * 10):]
                        LOG.info("group is: %s", each_group)
                        if each_group.strip().upper() == group.strip().upper():
                            LOG.info(
                                "group %s is already the group of user %s, skip adding.", group, user)
                            return None
                        else:
                            users = users + " " + each_group.strip()
                else:
                    users = sub_userprf
                users = users.strip()
                users = users + " " + group

            addmem_cmd.append("SUPGRPPRF(" + users + ")")
            return addmem_cmd

    def change_netserver_name(self, fqdn):
        LOG.info("IBMi distro version is %s", __ibmi_distro_version__)
        LOG.info("call change_netserver_name with input %s", fqdn)
        itool = iToolKit(iparm=0, iret=0, ids=1, irow=0)
        itool.add(iCmd('chgjob', 'CHGJOB CCSID(37)'))
        itool.call(itransport)
        chgjob = itool.dict_out('chgjob')

        if 'success' in chgjob:
            LOG.debug(chgjob['success'])
        else:
            LOG.debug(chgjob['error'])

        # CALL QZLSCHSN PARM(server_name domain_name 'text description or comment' X'00000000') ENDTCPSVR *NETSVR
        chg_netserver_cmd = ['system']
        log_chg_netserver_cmd = ['system']
        parm_option = "PARM(server_name domain_name \'text description or comment\' X\'00000000\')"
        server_name = (fqdn.split('.')[0])
        domain_name = fqdn[fqdn.find(server_name) + len(server_name)+1:]

        server_name = re.sub(r'\W', u'#', server_name)
        if len(server_name) > 8:
            server_name = server_name[0:8]
        parm_option = parm_option.replace(
            'server_name', "\'" + server_name + "\'")
        parm_option = parm_option.replace(
            'domain_name', "\'" + domain_name + "\'")
        chg_netserver_cmd.extend(['CALL', 'QZLSCHSN', parm_option])
        log_chg_netserver_cmd.extend(['CALL', 'QZLSCHSN', parm_option])
        try:
            LOG.debug(
                "Execute command %s", log_chg_netserver_cmd)
            util.subp(chg_netserver_cmd, logstring=log_chg_netserver_cmd)
        except Exception as e:
            LOG.error("Failed to change NetServer name by running command %s, error=%s",
                      log_chg_netserver_cmd, str(e))
        return False

    def change_IBMi_rdbdire(self, fqdn):
        # Discussed with Wang yun, AE takes care of the RDBDIRE configuration
        return False

    # MRDB related configuration function, funcation name starts with prefix mrdb_ or _mrdb_
    def _mrdb_create_line_description(self, resourcename, lind):
        rscname = 'RSRCNAME(' + resourcename + ')'
        line_description = 'LIND(' + lind + ')'
        crt_lined_cmd = ['system']
        log_crt_lined_cmd = ['system']
        crt_lined_cmd.extend(['CRTLINETH', line_description, rscname])
        log_crt_lined_cmd.extend(['CRTLINETH', line_description, rscname])
        try:
            LOG.debug("Execute command %s", log_crt_lined_cmd)
            util.subp(crt_lined_cmd, logstring=log_crt_lined_cmd)
        except Exception as e:
            LOG.error("Fail to execute command %s with error %s",
                      log_crt_lined_cmd, e)
            return False
        return True

    def _mrdb_delete_line_description(self, lind):
        # Incase there is a LIND named as lind but the resource is different
        cmd_str = 'DLTOBJ OBJ(*ALL/lind_name_replace) OBJTYPE(*LIND)'
        cmd_str = cmd_str.replace('lind_name_replace', lind)
        cmd = ['system', cmd_str]
        log_cmd = ['system', cmd_str]
        try:
            LOG.debug("Execute command %s", log_cmd)
            util.subp(cmd, logstring=log_cmd)
        except Exception as e:
            LOG.error("Fail to execute command %s with error %s", log_cmd, e)

    def _mrdb_get_all_ethernet_rscnames(self):
        self._mrdb_METHOD_ENTER(
            sys._getframe().f_code.co_name, sys._getframe().f_lineno)
        itool = iToolKit()
        itool.add(
            iSrvPgm('qgyrhr', 'QGYRHR', 'QgyRtvHdwRscList')
            .addParm(
                iDS('RHRL0100_t', {'len': 'rhrlen'})
                .addData(iData('rhrRet', '10i0', ''))
                .addData(iData('rhrAvl', '10i0', ''))
                .addData(iData('rhrNbr', '10i0', '', {'enddo': 'mycnt'}))
                .addData(iData('rhrLen', '10i0', ''))
                .addData(iDS('res_t', {'dim': '999', 'dou': 'mycnt'})
                         .addData(iData('resCat', '10i0', ''))
                         .addData(iData('resLvl', '10i0', ''))
                         .addData(iData('resLin', '10i0', ''))
                         .addData(iData('resNam', '10a', ''))
                         .addData(iData('resTyp', '4a', ''))
                         .addData(iData('resMod', '3a', ''))
                         .addData(iData('resSts', '1a', ''))
                         .addData(iData('resSys', '8a', ''))
                         .addData(iData('resAdp', '12a', ''))
                         .addData(iData('resDsc', '50h', ''))
                         .addData(iData('resKnd', '24b', ''))
                         )
            )
            .addParm(iData('rcvlen', '10i0', '', {'setlen': 'rhrlen'}))
            .addParm(iData('fmtnam', '10a', 'RHRL0100'))
            .addParm(iData('rescat', '10i0', '2'))
            .addParm(
                iDS('ERRC0100_t', {'len': 'errlen'})
                .addData(iData('errRet', '10i0', ''))
                .addData(iData('errAvl', '10i0', ''))
                .addData(iData('errExp', '7A', '', {'setlen': 'errlen'}))
                .addData(iData('errRsv', '1A', ''))
            )
        )
        # xmlservice
        itool.call(itransport)
        # output
        qgyrhr = itool.dict_out('qgyrhr')
        eth_resource_name = []
        roce_resource_name = []
        ip_resource_dict = {}
        roce_adapter_type = ['2CEC', '2CF3', '58FA', '58FB']

        if 'success' in qgyrhr:
            LOG.debug(qgyrhr['success'])
            LOG.debug("    Length of receiver variable......%s",
                      qgyrhr['rcvlen'])
            LOG.debug("    Format name......................%s",
                      qgyrhr['fmtnam'])
            LOG.debug("    Resource category................%s",
                      qgyrhr['rescat'])
            RHRL0100_t = qgyrhr['RHRL0100_t']
            LOG.debug("    RHRL0100_t:")
            LOG.debug("      Number of resources returned...%s",
                      RHRL0100_t['rhrNbr'])
            if int(RHRL0100_t['rhrNbr']) > 0:
                res_t = RHRL0100_t['res_t']
                # ip_resource_name will be the resource name for configuring ip
                for rec in res_t:
                    LOG.debug(
                        "        --------------------------------------------------------")
                    LOG.debug(
                        "        Resource name................%s", rec['resNam'])
                    LOG.debug(
                        "        Resource kind................%s", rec['resKnd'])
                    # May need to correct to the right kind for physical device
                    if rec['resKnd'] == "0000000000000008000000000000000400000800000004" \
                            or rec['resKnd'] == "0000000000000008000000000000000400000000000004":
                        # Resource type for all the current RoCE adapters (2CEC, 2CF3, 58FA, 58FB) support both RoCE v1 and v2.
                        if rec['resTyp'] in roce_adapter_type:
                            roce_resource_name.append(rec['resNam'])
                        else:
                            eth_resource_name.append(rec['resNam'])
                        location = self._mrdb_get_ethernet_location(
                            rec['resNam'])
                        ip_resource_dict[location] = rec['resNam']
        else:
            LOG.debug("Error when calling QgyRtvHdwRscList to to list all communication resources and their location code, error=%s", qgyrhr['error'])

        ip_resource_dict['roce'] = roce_resource_name
        ip_resource_dict['eth'] = eth_resource_name

        self._mrdb_METHOD_EXIT(
            sys._getframe().f_code.co_name, sys._getframe().f_lineno)
        return eth_resource_name, roce_resource_name, ip_resource_dict

    def _mrdb_get_rscname_by_hardware_location(self, location):
        self._mrdb_METHOD_ENTER(
            sys._getframe().f_code.co_name, sys._getframe().f_lineno)
        itool = iToolKit()
        itool.add(
            iSrvPgm('qgyrhr', 'QGYRHR', 'QgyRtvHdwRscList')
            .addParm(
                iDS('RHRL0100_t', {'len': 'rhrlen'})
                .addData(iData('rhrRet', '10i0', ''))
                .addData(iData('rhrAvl', '10i0', ''))
                .addData(iData('rhrNbr', '10i0', '', {'enddo': 'mycnt'}))
                .addData(iData('rhrLen', '10i0', ''))
                .addData(iDS('res_t', {'dim': '999', 'dou': 'mycnt'})
                         .addData(iData('resCat', '10i0', ''))
                         .addData(iData('resLvl', '10i0', ''))
                         .addData(iData('resLin', '10i0', ''))
                         .addData(iData('resNam', '10a', ''))
                         .addData(iData('resTyp', '4a', ''))
                         .addData(iData('resMod', '3a', ''))
                         .addData(iData('resSts', '1a', ''))
                         .addData(iData('resSys', '8a', ''))
                         .addData(iData('resAdp', '12a', ''))
                         .addData(iData('resDsc', '50h', ''))
                         .addData(iData('resKnd', '24b', ''))
                         )
            )
            .addParm(iData('rcvlen', '10i0', '', {'setlen': 'rhrlen'}))
            .addParm(iData('fmtnam', '10a', 'RHRL0100'))
            .addParm(iData('rescat', '10i0', '2'))
            .addParm(
                iDS('ERRC0100_t', {'len': 'errlen'})
                .addData(iData('errRet', '10i0', ''))
                .addData(iData('errAvl', '10i0', ''))
                .addData(iData('errExp', '7A', '', {'setlen': 'errlen'}))
                .addData(iData('errRsv', '1A', ''))
            )
        )
        # xmlservice
        itool.call(itransport)
        # output
        qgyrhr = itool.dict_out('qgyrhr')
        ip_resource_name = None

        if 'success' in qgyrhr:
            LOG.debug(qgyrhr['success'])
            LOG.debug("    Length of receiver variable......%s",
                      qgyrhr['rcvlen'])
            LOG.debug("    Format name......................%s",
                      qgyrhr['fmtnam'])
            LOG.debug("    Resource category................%s",
                      qgyrhr['rescat'])
            RHRL0100_t = qgyrhr['RHRL0100_t']
            LOG.debug('    RHRL0100_t:')
            LOG.debug("      Number of resources returned...%s",
                      RHRL0100_t['rhrNbr'])
            if int(RHRL0100_t['rhrNbr']) > 0:
                res_t = RHRL0100_t['res_t']
                cur_loc = None
                # ip_resource_name will be the resource name for configuring ip
                for rec in res_t:
                    LOG.debug(
                        "        --------------------------------------------------------")
                    LOG.debug(
                        "        Resource name................%s", rec['resNam'])
                    LOG.debug(
                        "        Resource kind................%s", rec['resKnd'])
                    if rec['resKnd'] == "0000000000000008000000000000000400000800000004" \
                            or rec['resKnd'] == "0000000000000008000000000000000400000000000004":
                        cur_loc = self._mrdb_get_ethernet_location(
                            rec['resNam'])
                        if cur_loc == location:
                            ip_resource_name = rec['resNam']
                            LOG.debug(
                                "Found Enthernet Port resource %s which has Location code %s", rec['resNam'], location)
                            self._mrdb_METHOD_EXIT(
                                sys._getframe().f_code.co_name, sys._getframe().f_lineno)
                            return ip_resource_name
        else:
            LOG.debug("Error when calling QgyRtvHdwRscList to get the resource names by location code, error=%s", qgyrhr['error'])
        self._mrdb_METHOD_EXIT(
            sys._getframe().f_code.co_name, sys._getframe().f_lineno)
        return ip_resource_name

    def _mrdb_get_ethernet_location(self, res_name):
        self._mrdb_METHOD_ENTER(
            sys._getframe().f_code.co_name, sys._getframe().f_lineno)
        itool = iToolKit()
        itool.add(
            iSrvPgm('qgyrhr', 'QGYRHR', 'QgyRtvHdwRscInfo')
            .addParm(
                iDS('RHRI0100_t', {'len': 'rhrlen'})
                .addData(iData('rhrRet', '10i0', ''))
                .addData(iData('rhrAvl', '10i0', ''))
                .addData(iData('sysBusNum', '10i0', ''))
                .addData(iData('sysBdNum', '10i0', ''))
                .addData(iData('sysCdNum', '10i0', ''))
                .addData(iData('IOBusAdd', '10i0', ''))
                .addData(iData('AdaptAdd', '10i0', ''))
                .addData(iData('PortNum', '10i0', ''))
                .addData(iData('srNum', '10a', ''))
                .addData(iData('partNum', '12a', ''))
                .addData(iData('frmID', '4a', ''))
                .addData(iData('cdPst', '5a', ''))
                .addData(iData('locCd', '79a', ''))
                .addData(iData('expSrNum', '15a', ''))
                .addData(iData('LANSpeed', '8a', '', {'hex': 'on'}))
                .addData(iData('LinkAgg', '1a', '', {'hex': 'on'}))
                .addData(iData('MAC', '6a', '', {'hex': 'on'}))
            )
            .addParm(iData('rcvlen', '10i0', '', {'setlen': 'rhrlen'}))
            .addParm(iData('fmtnam', '8a', 'RHRI0100'))
            .addParm(iData('resnam', '10a', res_name))
            .addParm(
                iDS('ERRC0100_t', {'len': 'errlen'})
                .addData(iData('errRet', '10i0', ''))
                .addData(iData('errAvl', '10i0', ''))
                .addData(iData('errExp', '7A', '', {'setlen': 'errlen'}))
                .addData(iData('errRsv', '1A', ''))
            )
        )

        # xmlservice
        itool.call(itransport)
        # output
        qgyrhr = itool.dict_out('qgyrhr')
        if 'success' in qgyrhr:
            LOG.debug(qgyrhr['success'])
            LOG.debug("    Format name......................%s",
                      qgyrhr['fmtnam'])
            LOG.debug("    Resource Name....................%s",
                      qgyrhr['resnam'])
            RHRI0100_t = qgyrhr['RHRI0100_t']
            LOG.debug("      RHRI0100_t:")
            if int(RHRI0100_t['rhrAvl']) > 0:
                loccode = RHRI0100_t['locCd']
                LOG.debug("        Location code................%s",
                          RHRI0100_t['locCd'])
                self._mrdb_METHOD_EXIT(
                    sys._getframe().f_code.co_name, sys._getframe().f_lineno)
                return loccode
        else:
            LOG.debug("Error when calling QgyRtvHdwRscInfo to retrieve location code from the resource name, error=%s", qgyrhr['error'])
            self._mrdb_METHOD_EXIT(
                sys._getframe().f_code.co_name, sys._getframe().f_lineno)
            return None

    # get resource name based on mac address
    def _mrdb_get_rscname_by_mac_address(self, hwaddress):
        self._mrdb_METHOD_ENTER(
            sys._getframe().f_code.co_name, sys._getframe().f_lineno)
        itool = iToolKit()
        itool.add(
            iSrvPgm('qgyrhr', 'QGYRHR', 'QgyRtvHdwRscList')
            .addParm(iDS('RHRL0100_t', {'len': 'rhrlen'})
                     .addData(iData('rhrRet', '10i0', ''))
                     .addData(iData('rhrAvl', '10i0', ''))
                     .addData(iData('rhrNbr', '10i0', '', {'enddo': 'mycnt'}))
                     .addData(iData('rhrLen', '10i0', ''))
                     .addData(iDS('res_t', {'dim': '999', 'dou': 'mycnt'})
                              .addData(iData('resCat', '10i0', ''))
                              .addData(iData('resLvl', '10i0', ''))
                              .addData(iData('resLin', '10i0', ''))
                              .addData(iData('resNam', '10a', ''))
                              .addData(iData('resTyp', '4a', ''))
                              .addData(iData('resMod', '3a', ''))
                              .addData(iData('resSts', '1a', ''))
                              .addData(iData('resSys', '8a', ''))
                              .addData(iData('resAdp', '12a', ''))
                              .addData(iData('resDsc', '50h', ''))
                              .addData(iData('resKnd', '24b', ''))
                              )
                     )
            .addParm(iData('rcvlen', '10i0', '', {'setlen': 'rhrlen'}))
            .addParm(iData('fmtnam', '10a', 'RHRL0100'))
            .addParm(iData('rescat', '10i0', '2'))
            .addParm(iDS('ERRC0100_t', {'len': 'errlen'})
                     .addData(iData('errRet', '10i0', ''))
                     .addData(iData('errAvl', '10i0', ''))
                     .addData(iData('errExp', '7A', '', {'setlen': 'errlen'}))
                     .addData(iData('errRsv', '1A', ''))
                     )
        )

        itool.call(itransport)
        qgyrhr = itool.dict_out('qgyrhr')
        mac_address = ""
        resource_name = ""
        cur_macaddr = hwaddress.upper().replace(":", "")
        LOG.debug("MAC address from meta_data: %s", cur_macaddr);
        if 'success' in qgyrhr:
            LOG.debug(qgyrhr['success'])
            LOG.debug("    Length of receiver variable......%s",
                      qgyrhr['rcvlen'])
            LOG.debug("    Format name......................%s",
                      qgyrhr['fmtnam'])
            LOG.debug("    Resource category................%s",
                      qgyrhr['rescat'])
            RHRL0100_t = qgyrhr['RHRL0100_t']
            LOG.debug("    RHRL0100_t:")
            LOG.debug("      Number of resources returned...%s",
                      RHRL0100_t['rhrNbr'])
            if int(RHRL0100_t['rhrNbr']) > 0:
                res_t = RHRL0100_t['res_t']
                # mac_resource_names will be the mapping of mac address and resource name for assigning ip address
                for rec in res_t:
                    LOG.debug(
                        "        --------------------------------------------------------")
                    LOG.debug(
                        "        Resource name................%s", rec['resNam'])
                    if rec['resKnd'] == "0000000000000008000000000000000400000800000004" \
                            or rec['resKnd'] == "0000000000000008000000000000000400000000000004":
                        LOG.debug(
                            "        Description..................%s", rec['resDsc'])
                        LOG.debug(
                            "        Resource kind................%s", rec['resKnd'])
                        
                        mac_address = self._mrdb_get_ethernet_mac(rec['resNam'])
                        if mac_address and cur_macaddr:
                            if cur_macaddr == mac_address:
                                resource_name = rec['resNam']
                                LOG.debug(
                                    "Found Enthernet Port resource %s which has MAC address %s", rec['resNam'], mac_address)                            
                if not resource_name:
                    LOG.error(
                        "Error when validating the MAC address %s from meta_data with the one from QgyRtvHdwRscInfo %s", cur_macaddr, mac_address)
                        
        else:
            LOG.debug("Error when calling QgyRtvHdwRscList to list communication resources and their hardware address, error=%s", qgyrhr['error'])
        self._mrdb_METHOD_EXIT(sys._getframe().f_code.co_name, sys._getframe().f_lineno)
        return resource_name

    def _mrdb_get_ethernet_mac(self, res_name):
        self._mrdb_METHOD_ENTER(
            sys._getframe().f_code.co_name, sys._getframe().f_lineno)
        itool = iToolKit()
        itool.add(
            iSrvPgm('qgyrhr', 'QGYRHR', 'QgyRtvHdwRscInfo', {'error': 'on'})
            .addParm(iDS('RHRI0100_t', {'len': 'rhrlen'})
                     .addData(iData('rhrRet', '10i0', ''))
                     .addData(iData('rhrAvl', '10i0', ''))
                     .addData(iData('sysBusNum', '10i0', ''))
                     .addData(iData('sysBdNum', '10i0', ''))
                     .addData(iData('sysCdNum', '10i0', ''))
                     .addData(iData('IOBusAdd', '10i0', ''))
                     .addData(iData('AdaptAdd', '10i0', ''))
                     .addData(iData('PortNum', '10i0', ''))
                     .addData(iData('srNum', '10a', ''))
                     .addData(iData('partNum', '12a', ''))
                     .addData(iData('frmID', '4a', ''))
                     .addData(iData('cdPst', '5a', ''))
                     .addData(iData('locCd', '79a', ''))
                     .addData(iData('expSrNum', '15a', ''))
                     .addData(iData('LANSpeed', '8a', '', {'hex': 'on'}))
                     .addData(iData('LinkAgg', '1a', '', {'hex': 'on'}))
                     .addData(iData('MAC', '6a', '', {'hex': 'on'}))
                     )
            .addParm(iData('rcvlen', '10i0', '', {'setlen': 'rhrlen'}))
            .addParm(iData('fmtnam', '8a', 'RHRI0100'))
            .addParm(iData('resnam', '10a', res_name))
            .addParm(
                iDS('ERRC0100_t', {'len': 'errlen'})
                .addData(iData('errRet', '10i0', ''))
                .addData(iData('errAvl', '10i0', ''))
                .addData(iData('errExp', '7A', '', {'setlen': 'errlen'}))
                .addData(iData('errRsv', '1A', ''))
            )
        )

        itool.call(itransport)
        qgyrhr = itool.dict_out('qgyrhr')

        mac = None
        if 'success' in qgyrhr:
            LOG.debug(qgyrhr['success'])
            LOG.debug("    Format name......................%s",
                      qgyrhr['fmtnam'])
            LOG.debug("    Resource Name....................%s", 
                      qgyrhr['resnam'])
            RHRI0100_t = qgyrhr['RHRI0100_t']
            LOG.debug("    RHRI0100_t:")
            if int(RHRI0100_t['rhrAvl']) > 0:
                mac = RHRI0100_t['MAC']
                LOG.debug("        Mac address................%s", mac)
                mac.ljust(12, '0')
                LOG.debug("        Mac address append 0.......%s", mac)
        else:
            LOG.debug("Error when calling QgyRtvHdwRscInfo to retrieve MAC address, error=%s", qgyrhr['error'])
        self._mrdb_METHOD_EXIT(
                sys._getframe().f_code.co_name, sys._getframe().f_lineno)
        return mac            

    def _mrdb_getQtcoHosts(self, ip):
        hosts_file = "/QIBM/USERDATA/OS400/TCPIP/QTOCHOSTS"
        hosts = []
        try:
            fp = open(hosts_file, "r")
            lines = fp.readlines()
            for line in lines:
                if ip in line:
                    hosts = line.split()
                    del hosts[0]
        except Exception as e:
            LOG.error("_mrdb_getQtcoHosts:Exception occurred, error=%s", str(e))
            if 'fp' in locals():
                fp.close()
            return hosts
        if 'fp' in locals():
            fp.close()
        return hosts

    # lind name must begin with an alphabetic character followed by alphanumeric characters or "_" and length less than 10
    def _mrdb_isValidLind(self, lind):
        if (lind == "") or (lind[0].isdigit() == True) or (len(lind) > 10):
            LOG.debug(
                "lind %s exceeds 10 characters or the first character is not valid", lind)
            return False
        count = 0
        while count < len(lind):
            if (not lind[count].isalnum()) and (lind[count] != "_"):
                LOG.debug("lind %s '%d' character '%c' is not valid",
                          lind, count, lind[count])
                return False
            count += 1
        return True

    # start engine
    def mrdb_start_engine(self):
        itool = iToolKit()
        itool.add(
            iSrvPgm('qmrdbapi', 'QMRDBAPI', 'QmrdbStartEngine')
            .addParm(
                iDS('MrdbSPIResult')
                .addData(iData('result', '10i0', ''))
                .addData(iData('additionalErrorCode', '10i0', ''))
                .addData(iData('offset', '10i0', ''))
                .addData(iData('reserved', '580a', ''))
            )
        )
        # xmlservice
        itool.call(itransport)
        # output
        qmrdbapi = itool.dict_out('qmrdbapi')
        MrdbSPIResult = qmrdbapi['MrdbSPIResult']
        LOG.debug(qmrdbapi)
        if 'success' in qmrdbapi:
            LOG.debug(qmrdbapi['success'])
        else:
            LOG.error(qmrdbapi['error'])

    # settings should be meta['network_config'], fqdn should be meta['hostname']
    def mrdb_write_IBMi_network(self, settings, fqdn, sts, bring_up=True):
        self._mrdb_METHOD_ENTER(
            sys._getframe().f_code.co_name, sys._getframe().f_lineno)
        self._mrdb_progress_log("ConfigNetwork", "START", "a+")
        have_error = False
        entries = settings['details']
        LOG.debug(
            "translated ubuntu style network settings %s into %s", settings, entries)
        eth_rscnames, roce_rscnames, ip_rscname_dict = self._mrdb_get_all_ethernet_rscnames()
        all_com_rscnames = eth_rscnames + roce_rscnames
        LOG.debug("all_com_rscnames=%s", all_com_rscnames)
        LOG.debug("eth_rscnames=%s", eth_rscnames)
        LOG.debug("roce_rscnames=%s", roce_rscnames)
        LOG.debug("ip_rscname_dict=%s", ip_rscname_dict)

        if len(all_com_rscnames) == 0:
            LOG.error("Fatal error: No communication resources found")
            self._mrdb_progress_log("ConfigNetwork", "FAILED", "a+")
            return False

        if len(eth_rscnames) > 0:
            rmc_rscname = eth_rscnames[len(eth_rscnames) - 1]
            LOG.debug("Select %s as rmc_rscname", rmc_rscname)
        else:
            rmc_rscname = None

        if fqdn and fqdn.find(".") > 0:
            toks = str(fqdn).split(".")
            hostname = toks[0]
        else:
            hostname = fqdn
        LOG.debug("hostname=%s", hostname)

        # Configure Service Tools Server(STS)
        if sts:
            self._mrdb_progress_log("ConfigSTS", "START", "a+")     
            try: 
                LOG.debug("STS: Start updating configuration")
                cursor = conn.cursor()

                value_max_lengths = {
                    "action": 10,
                    "ip_version": 4,
                    "ipv4_address": 15,
                    "gateway_address": 15,
                    "subnet_mask": 15,
                    "ipv6_address": 45,
                    "virtual_lan_id": 4,
                    "interface_id": 16,
                    "resource_name": 10,
                    "server_name": 12,
                    "duplex": 4,
                    "network_speed": 4
                }
                # Debug: verify current user
                cursor.execute("SELECT CURRENT_USER FROM SYSIBM.SYSDUMMY1")
                current_user = cursor.fetchone()[0]
                LOG.debug("STS: current user:%s", current_user)           
                LOG.debug("STS: prepare the SQL CALL statement with parameters based upon metadata")

                sql_key = []
                sql_values = []
                LOG.debug("sts:%s", sts)
                for key, value in sts.items():
                    if value and value.strip():
                        length = value_max_lengths.get(key,45)
                        # Get resource name based upon cmn_location
                        if key == "cmn_location":
                            for k, val in ip_rscname_dict.items():
                                LOG.debug("cmn_location:%s, resource_name:%s", k, val)
                                if value == k:
                                    LOG.debug("STS: found matching cmn_location:%s, resource_name:%s", k, val)
                                    sql_key.append(f"resource_name => CAST(? AS VARCHAR(10) CCSID 37)")
                                    sql_values.append(val.strip())
                                    break
                        else:
                            sql_key.append(f"{key} => CAST(? AS VARCHAR({length}) CCSID 37)")
                            sql_values.append(value.strip())

                # Build SQL CALL statement dynamically
                sql = f"CALL QSYS2.CHANGE_SERVICE_TOOLS_SERVER({', '.join(sql_key)})"
                LOG.debug("STS: generated SQL: %s", sql)
                LOG.debug("STS: SQL values: %s", sql_values)

                cursor.execute(sql, sql_values)
                conn.commit()
                LOG.debug("STS configuration updated successfully")
                self._mrdb_progress_log("ConfigSTS", "SUCCESS", "a+")  

            except Exception as e:
                LOG.error("Unexpect error: %s", str(e))
                self._mrdb_progress_log("ConfigSTS", "FAILED", "a+") 
            except dbi.ProgrammingError as e:
                LOG.error("Database error: %s", str(e))
                self._mrdb_progress_log("ConfigSTS", "FAILED", "a+") 
            except dbi.InterfaceError as e:
                LOG.error("Connection error: %s", str(e))  
                self._mrdb_progress_log("ConfigSTS", "FAILED", "a+")      
            except dbi.OperationalError as e:
                LOG.error("Operational error: %s", str(e))
                self._mrdb_progress_log("ConfigSTS", "FAILED", "a+")       

        # Make the intermediate format as the rhel format...
        create_dhcp_file = True
        gateway = "NOTSET"

        gateway_list = {}
        nameservers = []
        searchsvrs = []
        lind_created = []
        index_lind = 0

        for info in entries:
            LOG.debug("info=%s in network_config details", info)
            rmc_ethernet = False
            run_cmd = 0
            chdev_cmd = ['system']
            log_chdev_cmd = ['system']
            mtu_option = "NOTSET"

            aix_dev = IBMi_util.translate_devname(info['device'])
            LOG.debug("dev=%s, aix_dev=%s", info['device'], aix_dev)

            # dup write this dns and dns_search here to avoid some 'continue' condition cause the dns and dns_search configure failure
            if 'dns_nameservers' in info:
                nameservers.extend(info['dns_nameservers'])
                LOG.debug("dns_nameservers is %s", info['dns_nameservers'])
            if 'dns_search' in info:
                searchsvrs.extend(info['dns_search'])
                LOG.debug("searchservers is %s", info['dns_search'])

            if info.get('bootproto') == 'dhcp':
                IBMi_util.config_dhcp(aix_dev, info, create_dhcp_file)
                create_dhcp_file = False
            else:
                chdev_cmd.append('ADDTCPIFC')
                log_chdev_cmd.append('ADDTCPIFC')

                if info['ipv6'] == True or info['ipv4'] == True:
                    run_cmd = 1

                chdev_opts = {
                    "address": 'INTNETADR(ipaddress)',
                    "netmask": 'SUBNETMASK(mask)',
                    "gateway": 'NEXTHOP(gateway)',
                }

                for (key, val) in info.items():
                    LOG.debug("key=%s val=%s in info.iteritem", key, val)
                    if key in 'mtu':
                        mtu_option = "MTU(" + val + ")"
                        LOG.debug(
                            "mtu=%s, mtu_option=%s", info['mtu'], mtu_option
                            )
                    if key in chdev_opts and val and isinstance(val, basestring):
                        if key in 'netmask':
                            val = "\'" + val + "\'"
                            chdev_cmd.append(
                                chdev_opts[key].replace('mask', val))
                            log_chdev_cmd.append(
                                chdev_opts[key].replace('mask', val))
                        if key in 'gateway':
                            gateway = "\'" + val + "\'"

                # formulate the line-description name here
                if rmc_ethernet:
                    lined = 'SECRMC'
                    self._mrdb_delete_line_description(lined)
                    lind_result = self._mrdb_create_line_description(
                        rmc_rscname, lined)
                    if lind_result:
                        LOG.debug("LIND SECRMC for secure RMC created")
                    else:
                        LOG.debug(
                            "Failed to create LIND SECRMC for secure RMC")
                else:
                    if 'cmnlocation' in info and info['cmnlocation'] != '' and info['cmnlocation'] is not None:
                        location = info['cmnlocation']
                        LOG.debug(
                            "Configure the IP interface base on the cmnlocation %s", location)
                        rscname = self._mrdb_get_rscname_by_hardware_location(
                            location)
                    else:
                        # if cmnlocation is unavailable, use hwaddress
                        if 'hwaddress' in info:
                            macaddress = info['hwaddress']
                            LOG.debug(
                                "cmnlocation not found in %s, Configure the IP interface base on the MAC address: %s", info, macaddress)
                            rscname = self._mrdb_get_rscname_by_mac_address(macaddress)
                        else:
                            LOG.error(
                                "Fatal Error: fail to get hardware address from %s", info
                            )                        
                    if rscname:
                        LOG.debug(
                            "rscname %s found for TCPIP interface %s", rscname, info)
                    else:
                        LOG.error(
                            "Fatal Error: fail to get ethernet resource for %s", info)
                        have_error = True
                        continue
                    if 'lind' in info and info['lind'].strip() != '':
                        lined = info['lind'].strip().upper()
                        LOG.debug("lined get from meta_data is %s", lined)
                        if not self._mrdb_isValidLind(lined):
                            LOG.debug(
                                "lined %s get from meta_data is not a valid name", lined)
                            lined = "MRDB" + rscname
                            LOG.debug(
                                "Use generic name %s as lind name", lined)
                    else:
                        lined = "MRDB" + rscname
                        while True:
                            if lined in lind_created and index_lind < 99:
                                lined = "MRDBLINE" + str(index_lind)
                                index_lind = index_lind + 1
                            else:
                                break
                        LOG.debug(
                            "Key 'lind' does not exist in meta_data, use generic name %s as lind name", lined)
                    if lined not in lind_created:
                        self._mrdb_delete_line_description(lined)
                        lind_result = self._mrdb_create_line_description(
                            rscname, lined)
                        if lind_result:
                            LOG.debug("LIND " + lined +
                                      " created for resource " + rscname)
                            # avoid to create the existed lined
                            lind_created.append(lined)
                        else:
                            LOG.debug("Fail to create LIND " +
                                      lined + " for resource " + rscname)
                            have_error = True
                            continue
                if info['ipv4']:
                    chdev_cmd.append("LIND(" + lined + ")")
                    log_chdev_cmd.append("LIND(" + lined + ")")
                else:
                    vlanID = "*NONE"
                    if 'vlanID' in info:
                        vlanID = info['vlanID']
                    chdev_cmd.append("LIND(" + lined + " " + vlanID + ")")
                    log_chdev_cmd.append("LIND(" + lined + " " + vlanID + ")")
                    prefixLen = "64"
                    if 'prefixLen' in info:
                        prefixLen = info['prefixLen']
                    chdev_cmd.append("ADRPFXLEN(" + prefixLen + ")")
                    log_chdev_cmd.append("ADRPFXLEN(" + prefixLen + ")")

                # multiple ipaddress support
                for ip in info['address']:
                    ipAddr = ip
                    ip = "\'" + ip + "\'"
                    ipv4address = ip
                    intnetadr_parm = "INTNETADR(ipaddress)"
                    intnetadr_parm = intnetadr_parm.replace('ipaddress', ip)
                    chdev_cmd.append(intnetadr_parm)
                    log_chdev_cmd.append(intnetadr_parm)

                    if run_cmd:
                        try:
                            LOG.debug("Execute command %s", log_chdev_cmd)
                            util.subp(chdev_cmd, logstring=log_chdev_cmd)
                        except Exception as e:
                            have_error = True
                            LOG.error(
                                "Failed to execute command %s with error %s", log_chdev_cmd, e)
                    chdev_cmd.pop()  # delete the 'INTNETADR(ipaddress)' from the chdev_cmd so we can add it again for next ip address
                    log_chdev_cmd.pop()

                    # execute ADDTCPRTE cmd if this is a normal tcp ethernet
                    # duplicate run ADDTCPRTE is harmless, if the default is already existed, ADDTCPRTE will send msg "TCP/IP route already exists"
                    if (not rmc_ethernet) and (gateway != "NOTSET"):
                        gateway_list[gateway] = True
                        add_tcp_rt_cmd = ['system']
                        log_add_tcp_rte_cmd = ['system']
                        next_hop_option = "NEXTHOP(" + gateway + ")"
                        if info['ipv4']:
                            # MTU set to *IFC when it does not exist in meta_data
                            if (mtu_option != "NOTSET"):
                                add_tcp_rt_cmd.extend(
                                    ['ADDTCPRTE', "RTEDEST(*DFTROUTE)", next_hop_option, mtu_option])
                                log_add_tcp_rte_cmd.extend(
                                    ['ADDTCPRTE', "RTEDEST(*DFTROUTE)", next_hop_option, mtu_option])
                            else:                            
                                add_tcp_rt_cmd.extend(
                                    ['ADDTCPRTE', "RTEDEST(*DFTROUTE)", next_hop_option, "MTU(*IFC)"])
                                log_add_tcp_rte_cmd.extend(
                                    ['ADDTCPRTE', "RTEDEST(*DFTROUTE)", next_hop_option, "MTU(*IFC)"])
                        if info['ipv6']:  # ipv4 and ipv6 can not both be true
                            add_tcp_rt_cmd.extend(
                                ['ADDTCPRTE', "RTEDEST(*DFT6ROUTE)", next_hop_option, "BINDLIND(" + lined + ") ADRPFXLEN(*NONE)"])
                            log_add_tcp_rte_cmd.extend(
                                ['ADDTCPRTE', "RTEDEST(*DFT6ROUTE)", next_hop_option, "BINDLIND(" + lined + ") ADRPFXLEN(*NONE)"])
                        try:
                            LOG.debug("Execute command %s", log_add_tcp_rte_cmd)
                            util.subp(add_tcp_rt_cmd,
                                      logstring=log_add_tcp_rte_cmd)
                        except Exception as e:
                            have_error = True
                            LOG.error(
                                "Fail to execute command %s with error %s", log_add_tcp_rte_cmd, e)

                    if 'dns_nameservers' in info:
                        for dns_ns in info['dns_nameservers']:
                            if dns_ns not in nameservers:
                                nameservers.append(dns_ns)
                        LOG.debug("dns_nameservers is %s",
                                  info['dns_nameservers'])
                    if 'dns_search' in info:
                        searchsvrs.extend(info['dns_search'])
                        searchsvrs = [s.strip() for s in searchsvrs]
                        while '' in searchsvrs:
                            searchsvrs.remove('')
                        LOG.debug("searchservers is %s", info['dns_search'])
                        if searchsvrs:
                            LOG.debug(
                                "After dealing with blank, searchsvrs is %s", searchsvrs)

                    if rmc_ethernet == False:
                        chg_hosttable_cmd = ['system']
                        log_chg_hosttable_cmd = ['system']
                        # ADDTCPHTE INTNETADR('x.x.x.x') HOSTNAME(ETHERNETHOST) TEXT('ETHERNETHOST on Ethernet subnet')
                        allHosts = []
                        newHosts = []
                        existedHosts = self._mrdb_getQtcoHosts(ipAddr)
                        allHosts.extend(existedHosts)
                        LOG.debug("Exist hosts for IP %s are %s",
                                  ipAddr, existedHosts)

                        address_option = 'INTNETADR(' + ipv4address + ')'
                        fullhostname = "\'" + hostname + "\'"
                        if 'dns_search' in info:
                            for s in info['dns_search']:
                                if s.strip() != '':
                                    newHosts.append(
                                        (hostname + '.' + s).upper())
                        LOG.debug("New hosts are %s", newHosts)

                        for s in newHosts:
                            if s not in allHosts:
                                allHosts.append(s)
                        allHosts = list(set(allHosts))  # Remove duplicate
                        LOG.debug("All hosts are %s", allHosts)

                        for s in allHosts:
                            if s != hostname:  # hostname already in fullhostname string
                                fullhostname = fullhostname + " " + "\'" + s + "\'"

                        fullhostname = fullhostname.strip().upper()
                        hostname_option = 'HOSTNAME(' + fullhostname + ')'
                        if len(existedHosts) == 0:
                            chg_hosttable_cmd.extend(
                                ['ADDTCPHTE', address_option, hostname_option])
                            log_chg_hosttable_cmd.extend(
                                ['ADDTCPHTE', address_option, hostname_option])
                        else:
                            chg_hosttable_cmd.extend(
                                ['CHGTCPHTE', address_option, hostname_option])
                            log_chg_hosttable_cmd.extend(
                                ['CHGTCPHTE', address_option, hostname_option])

                        try:
                            LOG.debug("Execute command %s", log_chg_hosttable_cmd)
                            util.subp(chg_hosttable_cmd,
                                      logstring=log_chg_hosttable_cmd)
                        except Exception as e:
                            have_error = True
                            LOG.error(
                                "Fail to execute command %s with error %s", log_chg_hosttable_cmd, e)

                    vary_config_cmd = ['system']
                    log_vary_config_cmd = ['system']
                    vary_config_cmd.extend(
                        ['VRYCFG', 'CFGOBJ(' + lined + ') CFGTYPE(*LIN) STATUS(*ON)'])
                    log_vary_config_cmd.extend(
                        ['VRYCFG', 'CFGOBJ(' + lined + ') CFGTYPE(*LIN) STATUS(*ON)'])
                    try:
                        LOG.debug("Execute command %s", log_vary_config_cmd)
                        util.subp(vary_config_cmd,
                                  logstring=log_vary_config_cmd)
                    except Exception as e:
                        have_error = True
                        LOG.error(
                            "Failed to execute command %s with error %s", log_vary_config_cmd, e)

        chg_tcp_domain_cmd = ['system']
        log_chg_tcp_domain_cmd = ['system']
        host_option = "HOSTNAME(samplehost)"
        domain_option = "DMNNAME(sampledomain)"
        search_option = "DMNSCHLIST(samplesearchlist)"
        dns_options = "INTNETADR(sampledns)"

        searchservers = "\'"
        if searchsvrs:
            searchservers = searchservers + searchsvrs[0] + " "
            searchsvrset = set(searchsvrs)
            searchsvrset.remove(searchsvrs[0])
            for s in searchsvrset:
                searchservers = searchservers + s + " "
        searchservers = searchservers.strip()
        searchservers = searchservers + "\'"

        dns_s = ["*NONE", "*NONE", "*NONE"]
        dnsservers = ""
        if nameservers:
            for index in range(min(len(nameservers), 3)):
                dns_s[index] = nameservers[index]
            for s in dns_s:
                if s == "*NONE":
                    dnsservers = dnsservers + ' ' + s
                else:
                    dnsservers = dnsservers + ' ' + "\'" + s + "\'"
        else:
            dnsservers = "*NONE *NONE *NONE"
        dnsservers = dnsservers.strip()

        dns_options = dns_options.replace('sampledns', dnsservers).upper()
        search_option = search_option.replace(
            'samplesearchlist', searchservers).upper()
        host_option = host_option.replace(
            'samplehost', "\'" + hostname + "\'").upper()
        # Just pick up the first domain server as the DMANAME, and it already contains the left quote, so just append the right one here
        if searchsvrs:
            domain_option = domain_option.replace(
                'sampledomain', "\'" + searchsvrs[0] + "\'").upper()
        else:
            domain_option = domain_option.replace('sampledomain', "''").upper()
            LOG.debug("DMNNAME is BLANK, change the HOSTNAME to *NONE")
            host_option = "HOSTNAME(samplehost)"
            host_option = host_option.replace(
                'samplehost', "\'" + "*NONE" + "\'").upper()

        chg_tcp_domain_cmd.extend(
            ['CHGTCPDMN', host_option, domain_option, search_option, dns_options])
        log_chg_tcp_domain_cmd.extend(
            ['CHGTCPDMN', host_option, domain_option, search_option, dns_options])

        try:
            LOG.debug("Execute command %s", log_chg_tcp_domain_cmd)
            util.subp(chg_tcp_domain_cmd, logstring=log_chg_tcp_domain_cmd)
        except Exception as e:
            have_error = True
            LOG.error("Fail to execute command %s with error %s",
                      log_chg_tcp_domain_cmd, e)

        # Use CHGTCPIFC to change the IP address in non_autostart_ip[] to AUTOSTART(*NO)
        # So that these interfaces are not automatically started when the TCP/IP stack is activated by the Start TCP/IP (STRTCP) command.
        # It's a requirement for IP switching for Db2Mirror
        non_autostart_ip = []
        if 'non_autostart_ip' in settings:
            non_autostart_ip = settings['non_autostart_ip']
            LOG.info(
                "TCP interfaces %s in Db2Mirror IP switching group do not need to start during IPL", non_autostart_ip)
            if len(non_autostart_ip) != 0:
                LOG.info("Change TCPIP interface %s to AUTOSTART(*NO)",
                         non_autostart_ip)
                for ip_address in non_autostart_ip:
                    chgtcpifc_cmd_str = "QSYS/CHGTCPIFC INTNETADR(" + \
                        "\'" + ip_address + "\'" + ") AUTOSTART(*NO)"
                    chgtcpifc_cmd = ['system', chgtcpifc_cmd_str]
                    log_chgtcpifc_cmd = ['system', chgtcpifc_cmd_str]
                    try:
                        LOG.debug("Execute command %s", log_chgtcpifc_cmd)
                        util.subp(chgtcpifc_cmd, logstring=log_chgtcpifc_cmd)
                    except Exception as e:
                        LOG.error("Fail to execute command %s with error %s",
                                  log_chgtcpifc_cmd, e)
        # Db2 Mirror configuration should always start the TCP
        LOG.debug("About to start the TCP......")
        start_tcp_cmd = ['system']
        log_start_tcp_cmd = ['system']
        start_tcp_cmd.append("STRTCP")
        log_start_tcp_cmd.append("STRTCP")
        try:
            LOG.debug("Execute command %s", log_start_tcp_cmd)
            util.subp(start_tcp_cmd, logstring=log_start_tcp_cmd)
        except Exception as e:
            have_error = True
            LOG.error("Fail to execute command %s with error %s",
                      log_start_tcp_cmd, e)
        self._mrdb_METHOD_EXIT(
            sys._getframe().f_code.co_name, sys._getframe().f_lineno)
        if have_error:
            self._mrdb_progress_log("ConfigNetwork", "SuccessWithError", "a+")
        else:
            self._mrdb_progress_log("ConfigNetwork", "SUCCESS", "a+")
        return True

    # IBM i Network Redundancy Groups for MRDB
    # nrgs is from meta_data['nrgs']
    def mrdb_add_nrgs(self, nrgs):
        self._mrdb_METHOD_ENTER(
            sys._getframe().f_code.co_name, sys._getframe().f_lineno)
        self._mrdb_progress_log("ConfigNRGs", "START", "a+")
        LOG.info("Call mrdb_add_nrgs with arguments %s", str(nrgs))
        itool = iToolKit(iparm=0, iret=0, ids=1, irow=0)
        itool.add(iCmd('chgjob', 'CHGJOB CCSID(37)'))
        itool.call(itransport)
        chgjob = itool.dict_out('chgjob')

        if 'success' in chgjob:
            LOG.debug(chgjob['success'])
        else:
            LOG.debug(chgjob['error'])

        nrgConfigState = self.mrdb_QmrdbRtvNrgCfgState()
        LOG.debug("mrdb_QmrdbRtvNrgCfgState return " + str(nrgConfigState))
        if nrgConfigState != 2: # MrdbConfigComplete
            LOG.debug("Remove the default NRGs firstly in case AE fail to clean it up")
            self.mrdb_cleanup_NRGs()
            LOG.debug("Default NRGs removed")
        else:
            LOG.debug("Current NRG config state is MrdbConfigComplete, do not remove NRG") 

        # CALL PGM(QSYS/QMRDBNRG) PARM('QIBMIFS' '1' 'group description' '1' '2' '9.5.94.95 lind 123 2.2.2.2 1 0' '123.234.345.456 lind2 223 4.22.2.2 1 0')
        for item in nrgs:
            add_nrgs_cmd_str = \
                "CALL PGM(QSYS/QMRDBNRG) PARM(groupName groupType groupDesc loadBalLinkCount pairCount nrgIPAddrPairs)"

            groupName = item['groupName']
            groupType = str(item['groupType'])
            loadBalLinkCount = str(item['loadBalLinkCount'])
            pairCount = str(len(item['nrgIPAddrPairs']))
            if 'groupDesc' in item:
                groupDesc = item['groupDesc']
            else:
                groupDesc = 'Db2 Mirror'

            nrgIPAddrPairs = ""
            for i in range(0, len(item['nrgIPAddrPairs'])):
                ippair = item['nrgIPAddrPairs'][i]

                localAddr = ippair['localAddr']
                remoteAddr = ippair['remoteAddr']
                pairPriority = str(ippair['pairPriority'])

                if 'localLind' in ippair:
                    localLind = ippair['localLind'].strip()
                else:
                    localLind = "default"

                if 'localVLANID' in ippair:
                    localVLANID = str(ippair['localVLANID']).strip()
                else:
                    localVLANID = "0"

                if 'pairType' in ippair:
                    pairType = str(ippair['pairType']).strip()
                else:
                    pairType = "0" # default RoCE version as v1. 0 means v1, 1 means v2

                nrgIPAddrPairs += localAddr + " " + localLind + " " + localVLANID + \
                    " " + remoteAddr + " " + pairPriority + " " + pairType
                # if not the last item, need append ' ' between each items
                if i != len(item['nrgIPAddrPairs']) - 1:
                    nrgIPAddrPairs += "' '"

            add_nrgs_cmd_str = add_nrgs_cmd_str.replace(
                'groupName', "'" + groupName + "'").replace(
                    'groupType', "'" + groupType + "'").replace(
                        'groupDesc', "'" + groupDesc + "'").replace(
                            'loadBalLinkCount', "'" + loadBalLinkCount + "'").replace(
                                'pairCount', "'" + pairCount + "'").replace(
                                    'nrgIPAddrPairs', "'" + nrgIPAddrPairs + "'")
            add_nrgs_cmd = ['system', add_nrgs_cmd_str]
            log_add_nrgs_cmd = ['system', add_nrgs_cmd_str]
            try:
                LOG.debug("Execute command %s", log_add_nrgs_cmd)
                util.subp(add_nrgs_cmd, logstring=log_add_nrgs_cmd)
            except Exception as e:
                LOG.error("Fail to execute command %s for group %s with error %s",
                          log_add_nrgs_cmd, groupName, str(e))
                self._mrdb_METHOD_EXIT(
                    sys._getframe().f_code.co_name, sys._getframe().f_lineno)
                self._mrdb_progress_log("ConfigNRGs", "FAILED", "a+")
                return False
        # Tell Engine Controller NRG is ready to start
        self._mrdb_progress_log("NRGReady", "START", "a+")
        if self.mrdb_QmrdbTellEngCtlrNrgReady() == 0:
            LOG.debug("Call mrdb_QmrdbTellEngCtlrNrgReady() successful")
            self._mrdb_progress_log("NRGReady", "SUCCESS", "a+")
        else:
            LOG.error("Call mrdb_QmrdbTellEngCtlrNrgReady() failed")
            self._mrdb_progress_log("NRGReady", "FAILED", "a+")
            self._mrdb_progress_log("ConfigNRGs", "FAILED", "a+")
            return False

        self._mrdb_progress_log("ConfigNRGs", "SUCCESS", "a+")
        self._mrdb_METHOD_EXIT(
            sys._getframe().f_code.co_name, sys._getframe().f_lineno)
        return True

    # Build a parm string with an array, used for multi values parm for CL command
    # sep can be ' " or space
    # array input ['9.1.1.1','9.2.2.2','9.3.3.3','9.4.4.4']
    # sep is '           -->         '9.1.1.1' '9.2.2.2' '9.3.3.3' '9.4.4.4'
    # sep is "           -->         "9.1.1.1" "9.2.2.2" "9.3.3.3" "9.4.4.4"
    # sep is None or space -->         9.1.1.1   9.2.2.2  9.3.3.3  9.4.4.4
    def _mrdb_build_parm_from_array(self, parm_array, sep):
        self._mrdb_METHOD_ENTER(
            sys._getframe().f_code.co_name, sys._getframe().f_lineno)
        if not sep:
            sep = ""
        parmStr = sep
        for i in range(0, len(parm_array)):
            parmStr = parmStr + parm_array[i]
            if i != len(parm_array) - 1:
                if sep != "":
                    parmStr = parmStr + sep + " " + sep
                else:
                    parmStr += " "
        parmStr += sep
        self._mrdb_METHOD_EXIT(
            sys._getframe().f_code.co_name, sys._getframe().f_lineno)
        return parmStr

    def mrdb_QmrdbRmvNrg(self):
        itool = iToolKit()
        itool.add(
            iSrvPgm('qmrdbapi', 'QMRDBAPI', 'QmrdbRmvNrg')
            .addParm(
                iData('rtn', '10i0', '')
            )
        )
        # xmlservice
        itool.call(itransport)
        # output
        qmrdbapi = itool.dict_out('qmrdbapi')
        LOG.debug(qmrdbapi)
        if 'success' in qmrdbapi:
            LOG.debug(qmrdbapi['success'])
            return int(qmrdbapi['rtn'])
        else:
            LOG.error(qmrdbapi['error'])
        return -999

    def mrdb_QmrdbRtvNrgCfgState(self):
        itool = iToolKit()
        itool.add(
            iSrvPgm('qmrdbapi', 'QMRDBAPI', 'QmrdbRtvNrgCfgState')
                .addParm(
                iData('rState', '2i0', '')
                )
                .addParm(
                iDS('MrdbSPIResult')
                    .addData(iData('result', '10i0', ''))
                    .addData(iData('additionalErrorCode', '10i0', ''))
                    .addData(iData('offset', '10i0', ''))
                    .addData(iData('reserved', '52a', ''))
                )

        )
        # xmlservice
        itool.call(itransport)
        # output
        qmrdbapi = itool.dict_out('qmrdbapi')
        LOG.debug(qmrdbapi)
        MrdbSPIResult = qmrdbapi['MrdbSPIResult']
        if 'success' in qmrdbapi:
            LOG.debug(qmrdbapi['success'])
            if int(MrdbSPIResult['result']) == 0:
                return int(qmrdbapi['rState'])
        else:
            LOG.error(qmrdbapi['error'])
        return -999

    def mrdb_QmrdbSetNrgCfgState(self, newState):
        itool = iToolKit()
        itool.add(
            iSrvPgm('qmrdbapi', 'QMRDBAPI', 'QmrdbSetNrgCfgState')
            .addParm(iData('state', '2i0', str(newState), {'io': 'in'}))
            .addParm(
                iDS('MrdbSPIResult')
                .addData(iData('result', '10i0', ''))
                .addData(iData('additionalErrorCode', '10i0', ''))
                .addData(iData('offset', '10i0', ''))
                .addData(iData('reserved', '580a', ''))
            )
        )
        # xmlservice
        itool.call(itransport)
        # output
        qmrdbapi = itool.dict_out('qmrdbapi')
        MrdbSPIResult = qmrdbapi['MrdbSPIResult']
        LOG.debug(qmrdbapi)
        if 'success' in qmrdbapi:
            LOG.debug(qmrdbapi['success'])
            if int(MrdbSPIResult['result']) == 0:
                return 0
        else:
            LOG.error(qmrdbapi['error'])
        return -999

    def mrdb_QmrdbTellEngCtlrNrgReady(self):
        itool = iToolKit()
        itool.add(
            iSrvPgm('qmrdbapi', 'QMRDBAPI', 'QmrdbTellEngCtlrNrgReady')
            .addParm(
                iData('rtn', '10i0', '')
            )
        )
        # xmlservice
        itool.call(itransport)
        # output
        qmrdbapi = itool.dict_out('qmrdbapi')
        LOG.debug(qmrdbapi)
        if 'success' in qmrdbapi:
            LOG.debug(qmrdbapi['success'])
            return int(qmrdbapi['rtn'])
        else:
            LOG.error(qmrdbapi['error'])
        return -999

    def mrdb_QmrdbTellEngCtlrCfgComplete(self):
        itool = iToolKit()
        itool.add(
            iSrvPgm('qmrdbapi', 'QMRDBAPI', 'QmrdbTellEngCtlrCfgComplete')
            .addParm(
                iData('rtn', '10i0', '')
            )
        )
        # xmlservice
        itool.call(itransport)
        # output
        qmrdbapi = itool.dict_out('qmrdbapi')
        LOG.debug(qmrdbapi)
        if 'success' in qmrdbapi:
            LOG.debug(qmrdbapi['success'])
            return int(qmrdbapi['rtn'])
        else:
            LOG.error(qmrdbapi['error'])
        return -999

    def mrdb_cleanup_NRGs(self):
        self._mrdb_METHOD_ENTER(
            sys._getframe().f_code.co_name, sys._getframe().f_lineno)
        rc = True
        # remove NRGs
        if self.mrdb_QmrdbRmvNrg() == 0:
            LOG.debug("Call mrdb_QmrdbRmvNrg() successful")
            # set NRG config state to MrdbConfigNotReady '0'
            if self.mrdb_QmrdbSetNrgCfgState(0) == 0:
                LOG.debug("Call mrdb_QmrdbSetNrgCfgState(0) successful")
            else:
                LOG.error("Call mrdb_QmrdbSetNrgCfgState() failed")
                rc = False
        else:
            rc = False
            LOG.error("Call mrdb_QmrdbRmvNrg() failed")
        self._mrdb_METHOD_EXIT(
            sys._getframe().f_code.co_name, sys._getframe().f_lineno)
        return rc

    def _mrdb_METHOD_ENTER(self, func, line):
        msg = "Entering method " + func + ", line# " + str(line)
        LOG.info(msg)

    def _mrdb_METHOD_EXIT(self, func, line):
        msg = "Exiting method " + func + ", line# " + str(line)
        LOG.info(msg)

    def _mrdb_progress_log(self, name, status, mode):
        progress_log = "/var/log/progress.log"
        try:
            if mode.startswith("r"):
                if not os.path.exists(progress_log):
                    # Create an empty file if the file doesn't exist
                    fp = open(progress_log, "w+")
                    if 'fp' in locals():
                        fp.close()
                    return None
                else:
                    status = None
                    fp = open(progress_log, mode)
                    lines = fp.readlines()
                    for line in lines:
                        if name in line:
                            if "SUCCESS" in line:
                                status = "SUCCESS"
                            elif "FAILED" in line:
                                status = "FAILED"
                            elif "SuccessWithError" in line:
                                status = "SuccessWithError"
                    if 'fp' in locals():
                        fp.close()
                    return status
            else:
                fp = open(progress_log, mode)
                current_time = datetime.datetime.now()
                content = str(current_time) + " " + name + " " + status + "\n"
                fp.write(content)
                if 'fp' in locals():
                    fp.close()
                return True
        except Exception as e:
            LOG.error("_mrdb_progress_log:Exception occurred, error=%s", e)
            if mode.startswith("r"):
                if 'fp' in locals():
                    fp.close()
                return None
            else:
                if 'fp' in locals():
                    fp.close()
                return False

    def mrdb_set_configuration_complete(self):
        self._mrdb_METHOD_ENTER(
            sys._getframe().f_code.co_name, sys._getframe().f_lineno)
        rc = True
        if self.mrdb_QmrdbTellEngCtlrCfgComplete() == 0:
            LOG.debug("Call mrdb_QmrdbTellEngCtlrCfgComplete() successful")
        else:
            LOG.error("Call mrdb_QmrdbTellEngCtlrCfgComplete() failed")
            rc = False
        self._mrdb_METHOD_EXIT(
            sys._getframe().f_code.co_name, sys._getframe().f_lineno)
        return rc

    def mrdb_start_piranha(self):
        self._mrdb_METHOD_ENTER(
            sys._getframe().f_code.co_name, sys._getframe().f_lineno)
        cmd_str = "CALL PGM(QSMGSSTD) PARM('STARTPIR ' X'00000009' 'SSTD0100' X'00000000')"
        cmd = ['system', cmd_str]
        log_cmd = ['system', cmd_str]
        try:
            LOG.debug("Execute command %s", log_cmd)
            util.subp(cmd, logstring=log_cmd)
        except Exception as e:
            LOG.error("Fail to execute command %s with error %s", log_cmd, e)
        self._mrdb_METHOD_EXIT(
            sys._getframe().f_code.co_name, sys._getframe().f_lineno)
        return True

    def _mrdb_ipv4_addr(self, ip):
        p = re.compile(
            r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
        if p.match(ip):
            return True
        else:
            return False

    def _mrdb_ipv6_addr(self, addr):
        ip6_regex = (r'(\A([0-9a-f]{1,4}:){1,1}(:[0-9a-f]{1,4}){1,6}\Z)|'
                     r'(\A([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}\Z)|'
                     r'(\A([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}\Z)|'
                     r'(\A([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}\Z)|'
                     r'(\A([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}\Z)|'
                     r'(\A([0-9a-f]{1,4}:){1,6}(:[0-9a-f]{1,4}){1,1}\Z)|'
                     r'(\A(([0-9a-f]{1,4}:){1,7}|:):\Z)|(\A:(:[0-9a-f]{1,4})'
                     r'{1,7}\Z)|(\A((([0-9a-f]{1,4}:){6})(25[0-5]|2[0-4]\d|[0-1]'
                     r'?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})\Z)|'
                     r'(\A(([0-9a-f]{1,4}:){5}[0-9a-f]{1,4}:(25[0-5]|2[0-4]\d|'
                     r'[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})\Z)|'
                     r'(\A([0-9a-f]{1,4}:){5}:[0-9a-f]{1,4}:(25[0-5]|2[0-4]\d|'
                     r'[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|'
                     r'(\A([0-9a-f]{1,4}:){1,1}(:[0-9a-f]{1,4}){1,4}:(25[0-5]|'
                     r'2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d))'
                     r'{3}\Z)|(\A([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,3}:'
                     r'(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?'
                     r'\d?\d)){3}\Z)|(\A([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4})'
                     r'{1,2}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|'
                     r'[0-1]?\d?\d)){3}\Z)|(\A([0-9a-f]{1,4}:){1,4}(:[0-9a-f]'
                     r'{1,4}){1,1}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|'
                     r'2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A(([0-9a-f]{1,4}:){1,5}|:):'
                     r'(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?'
                     r'\d?\d)){3}\Z)|(\A:(:[0-9a-f]{1,4}){1,5}:(25[0-5]|2[0-4]\d|'
                     r'[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)')
        return bool(re.match(ip6_regex, addr))

    def mrdb_configuration(self, metadata, force=True):
        self._mrdb_METHOD_ENTER(
            sys._getframe().f_code.co_name, sys._getframe().f_lineno)

        if force:
            self._mrdb_progress_log("FORCERUN", "YES", "w")

        step_network = self._mrdb_progress_log("ConfigNetwork", None, "r")
        step_nrg = self._mrdb_progress_log("ConfigNRGs", None, "r")

        if step_network:
            LOG.debug("step_network:%s", step_network)
        else:
            LOG.debug("Network step does not exist")

        if step_nrg:
            LOG.debug("step_nrg:%s", step_nrg)
        else:
            LOG.debug("NRG step does not exist")

        if force:
            self._mrdb_progress_log("ParserMetadata", "START", "a+")
        else:
            self._mrdb_progress_log("ParserMetadata", "START", "w")

        if 'hostname' in metadata:
            hostname = metadata['hostname']
            LOG.debug("hostname in meta_data is %s", hostname)
            if self._mrdb_ipv4_addr(hostname) or self._mrdb_ipv6_addr(hostname):
                LOG.debug("Hostname is an IP address. Use 'name' instead")
                if 'name' in metadata:
                    hostname = metadata['name']
                    LOG.debug("Use system name %s as hostname", hostname)
                else:
                    LOG.error(
                        "Error: Host name is IP address and no system name in metadata")
        else:
            LOG.debug(
                "There is no 'hostname' in metadata or hostname is an IP address. Use 'name' instead")
            if 'name' in metadata:
                hostname = metadata['name']
                LOG.debug("Use system name %s as hostname", hostname)
            else:
                LOG.error(
                    "Fatal error: There is no hostname or system name in metadata")
                return False

        if 'network_config' in metadata:
            network_config = metadata['network_config']
            LOG.debug("network_config in meta_data:%s", network_config)
        else:
            LOG.error(" Fatal Error:There is no 'network_config' in metadata")
            return False

        if 'nrgs' in metadata:
            nrgs = metadata['nrgs']
            LOG.debug("nrg in meta_data:%s", nrgs)
        else:
            LOG.error("Fatal Error:There is no 'nrgs' in metadata")
            return False

        # Get Service Tools Server(STS) from metaData, it is optional
        if 'sts' in metadata:
            sts = metadata['sts']
            LOG.debug("sts in meta_data:%s", sts)
        else:
            sts = {}
            LOG.debug("There is no service tools server (STS) in metadata, continue")   

        self._mrdb_progress_log("ParserMetadata", "SUCCESS", "a+")

        self.mrdb_start_engine()

        if force:
            rc_network = self.mrdb_write_IBMi_network(
                network_config, hostname, sts, bring_up=True)
        else:
            if (not step_network) or (step_network == "FAILED"):
                rc_network = self.mrdb_write_IBMi_network(
                    network_config, hostname, sts, bring_up=True)
            else:
                LOG.debug(
                    "Skip mrdb_write_IBMi_network since this step has already completed")
                self._mrdb_progress_log("ConfigNetwork", step_network, "a+")
                rc_network = True

        if force:
            rc_nrg = self.mrdb_add_nrgs(nrgs)
        else:
            if (not step_nrg) or (step_nrg == "FAILED"):
                rc_nrg = self.mrdb_add_nrgs(nrgs)
            else:
                LOG.debug(
                    "Skip mrdb_add_nrgs since this step has already completed.")
                self._mrdb_progress_log("ConfigNRGs", step_nrg, "a+")
                rc_nrg = True

        if rc_network and rc_nrg:
            time.sleep(60)
            self._mrdb_progress_log("ConfigComplete", "START", "a+")
            if self.mrdb_set_configuration_complete():
                self._mrdb_progress_log("ConfigComplete", "SUCCESS", "a+")
            else:
                self._mrdb_progress_log("ConfigComplete", "FAILED", "a+")

        self.mrdb_start_piranha()
        self._mrdb_METHOD_EXIT(
            sys._getframe().f_code.co_name, sys._getframe().f_lineno)
        return True
