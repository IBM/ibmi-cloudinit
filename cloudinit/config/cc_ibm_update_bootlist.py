# =================================================================
# Licensed Materials - Property of IBM
#
# (c) Copyright IBM Corp. 2015 All Rights Reserved
#
# US Government Users Restricted Rights - Use, duplication or
# disclosure restricted by GSA ADP Schedule Contract with IBM Corp.
# =================================================================

import re

from cloudinit.settings import PER_INSTANCE
from cloudinit import util

frequency = PER_INSTANCE

BOOTINFO = '/usr/sbin/bootinfo'
BOOTLIST = '/usr/sbin/bootlist'
BOOTLIST_AIX = '/usr/bin/bootlist'
LSPROP = '/usr/sbin/lsprop'
CHOSEN_DEVICE_TREE = '/proc/device-tree/chosen'
OFPATHNAME = '/usr/sbin/ofpathname'
CPUINFO = '/proc/cpuinfo'
QEMU_STRING = 'emulated by qemu'


def handle(name, _cfg, _cloud, log, _args):
    log.debug('Attempting to configure the boot list.')
    system_info = util.system_info()

    if 'aix' in system_info['platform'].lower():
        try:
            boot_devices = util.subp([BOOTINFO,
                                      '-b'])[0].strip().split('\n')
            out = run_bootlist_command(log, mode='normal', fmt='logical',
                                       boot_devices=boot_devices,
                                       cmd_location=BOOTLIST_AIX)
            log.debug(out)
            return
        except util.ProcessExecutionError:
            util.logexc(log, 'Failed to set the bootlist.')
            raise

    if is_powerkvm(log):
        log.debug('Not configuring the boot list since this VM is running on '
                  'PowerKVM.')
        return

    architecture = system_info['uname'][4]
    if 'ppc' not in architecture:
        return

    orig_normal_bootlist = run_bootlist_command(log, mode='normal',
                                                fmt='ofpath').split('\n')
    orig_service_bootlist = run_bootlist_command(log, mode='service',
                                                 fmt='ofpath').split('\n')

    (dist, vers) = system_info['dist'][:2]
    major_release = (int)(vers.split('.')[0])
    device_paths = []
    if dist.startswith('Red Hat Enterprise Linux'):
        log.debug('RHEL version: %s' % vers)
        if major_release == 6:
            device_paths = get_device_paths_from_file(log, '/etc/yaboot.conf')
        else:
            device_paths = [get_last_booted_device(log)]
    elif dist.startswith('SUSE Linux Enterprise'):
        log.debug('SLES version: %s' % vers)
        if major_release == 11:
            device_paths = get_device_paths_from_file(log, '/etc/lilo.conf')
        else:
            device_paths = [get_last_booted_device(log)]
    elif dist.startswith('Ubuntu'):
        log.debug('Ubuntu version: %s' % vers)
        device_paths = [get_last_booted_device(log)]
    else:
        raise NotImplementedError('Not yet implemented for (%s, %s)' %
                                  (dist, vers))

    # Running the bootlist command using the ofpath format requires ofpathname
    # to work properly. On RHEL 6.4, ofpathname may fail if the 'bc' package
    # is not installed, causing bootlist to have some strange behavior when
    # setting the bootlist. In order to avoid setting an invalid bootlist, we
    # will fail if ofpathname does not work properly.
    # Example: `bootlist -m both -o` returns:
    #    ofpathname: 'bc' command not found. Please, install 'bc' package
    try:
        util.subp([OFPATHNAME])
    except util.ProcessExecutionError:
        util.logexc(log, 'The ofpathname command returned errors. Since the '
                    'bootlist command relies on ofpathname, these errors need '
                    'to be resolved.')
        raise

    if len(device_paths) > 0:
        out = run_bootlist_command(log, mode='both', fmt='ofpath',
                                   boot_devices=device_paths)
        log.debug(out)

    successful = (verify_bootlist(log, 'normal', orig_normal_bootlist) and
                  verify_bootlist(log, 'service', orig_service_bootlist))
    if not successful:
        msg = 'Failed to update the bootlist properly.'
        log.error(msg)
        raise Exception(msg)


def get_device_paths_from_file(log, conf_file):
    device_paths = []
    try:
        with open(conf_file, 'r') as f:
            conf_contents = f.read()
            device_paths = map(lambda s: s.strip(),
                               re.findall(r'^boot.*=(.*)', conf_contents,
                                          re.MULTILINE))
        return device_paths
    except:
        util.logexc(log, 'Failed to get device paths from conf file.')
        raise

    if len(device_paths) < 1:
        msg = 'No device paths were found in the conf file.'
        log.error(msg)
        raise Exception(msg)


def get_last_booted_device(log):
    try:
        lsprop_out = util.subp([LSPROP, CHOSEN_DEVICE_TREE])[0].strip()
        bootpath_matches = re.findall(r'^bootpath.*\"(.*)\"', lsprop_out,
                                      re.MULTILINE)
        if len(bootpath_matches) < 1:
            raise Exception('Did not find a bootpath entry in the lsprop '
                            'output:\n%s' % lsprop_out)
        device_in_ofpath_format = bootpath_matches[0].split(',')[0]
        device_in_logical_format = util.subp([OFPATHNAME, '-l',
                                              device_in_ofpath_format])[0]

        return device_in_logical_format.strip()
    except util.ProcessExecutionError:
        util.logexc(log, 'Failed to get the last booted device.')
        raise


def run_bootlist_command(log, mode, fmt, boot_devices=[],
                         cmd_location=BOOTLIST):
    if fmt == 'logical':
        fmt = '-o'
    elif fmt == 'ofpath':
        fmt = '-r'

    cmd = [cmd_location, '-m', mode, fmt]
    cmd += boot_devices

    try:
        out = util.subp(cmd)[0]
        return out.strip()
    except:
        util.logexc(log, 'Bootlist command failed.')
        raise


def verify_bootlist(log, mode, orig_bootlist):
    successful = True
    new_bootlist = run_bootlist_command(log, mode=mode, fmt='logical')
    log.debug('%s mode boot list in ofpath format before '
              'configuration: %s' % (mode.capitalize(), orig_bootlist))
    log.debug('%s mode boot list in logical format after '
              'configuration: %s' % (mode.capitalize(), new_bootlist))
    if new_bootlist.startswith('ofpathname'):
        successful = False
        log.warn('The updated %s mode bootlist is not correct. Attempting to '
                 'revert the change.' % mode)
        run_bootlist_command(log, mode=mode, fmt='ofpath',
                             boot_devices=orig_bootlist)

        # Check if the reversion was successful
        reverted_bootlist = run_bootlist_command(log, mode=mode, fmt='logical')
        if 'ofpathname' in reverted_bootlist:
            log.warn('Failed to revert the change, so attempting to use the '
                     'last booted device as the bootlist.')
            run_bootlist_command(log, mode=mode, fmt='ofpath',
                                 boot_devices=[get_last_booted_device(log)])
            last_chance_bootlist = run_bootlist_command(log, mode=mode,
                                                        fmt='logical')
            if 'ofpathname' not in last_chance_bootlist:
                successful = True

    return successful


def is_powerkvm(log):
    try:
        out = util.subp(['cat', CPUINFO])[0]
        return QEMU_STRING in out.lower()
    except:
        util.logexc(log, 'Failed to determine if VM is running on PowerKVM.')
        raise
