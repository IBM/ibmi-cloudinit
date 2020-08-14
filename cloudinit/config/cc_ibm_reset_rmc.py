# =================================================================
# Licensed Materials - Property of IBM
#
# (c) Copyright IBM Corp. 2015 All Rights Reserved
#
# US Government Users Restricted Rights - Use, duplication or
# disclosure restricted by GSA ADP Schedule Contract with IBM Corp.
# =================================================================

import os
import time

from cloudinit.settings import PER_INSTANCE
from cloudinit import util

frequency = PER_INSTANCE

PIDOF = 'pidof'
RMCCTRL = '/usr/sbin/rsct/bin/rmcctrl'
RECFGCT = '/usr/sbin/rsct/install/bin/recfgct'
SRCMSTR = '/sbin/srcmstr'

NODE_ID_FILE = '/etc/ct_node_id'

SRCMSTR_TIMEOUT_SECONDS = 30


def handle(name, _cfg, _cloud, log, _args):
    required_tools = [RMCCTRL, RECFGCT]
    for tool in required_tools:
        if not os.path.isfile(tool):
            log.debug('%s is not found but is required, therefore not '
                      'attempting to reset RMC.' % tool)
            return

    log.debug('Attempting to reset RMC.')
    system_info = util.system_info()

    node_id_before = get_node_id(log)
    log.debug('Node ID at beginning of module: %s' % node_id_before)

    # Stop the RMC subsystem and all resource managers so that we can make
    # some changes to it
    try:
        util.subp([RMCCTRL, '-z'])
    except:
        util.logexc(log, 'Failed to stop the RMC subsystem.')
        raise

    if 'linux' in system_info['platform'].lower():
        recycle_srcmstr_process(log)

    reconfigure_rsct_subsystems(log)

    node_id_after = get_node_id(log)
    log.debug('Node ID at end of module: %s' % node_id_after)

    if node_id_after == node_id_before:
        msg = 'New node ID did not get generated.'
        log.error(msg)
        raise Exception(msg)


def reconfigure_rsct_subsystems(log):
    # Reconfigure the RSCT subsystems, which includes removing all RSCT data
    # under the /var/ct directory, generating a new node ID, and making it
    # appear as if the RSCT components were just installed
    try:
        out = util.subp([RECFGCT])[0]
        log.debug(out.strip())
    except util.ProcessExecutionError:
        util.logexc(log, 'Failed to reconfigure the RSCT subsystems.')
        raise


def get_node_id(log):
    try:
        node_id = util.subp(['/usr/bin/head', '-n1', NODE_ID_FILE])[0].strip()
        return node_id
    except util.ProcessExecutionError:
        util.logexc(log, 'Failed to get node ID from file %s.' % NODE_ID_FILE)
        raise


def recycle_srcmstr_process(log):
    try:
        out = util.subp([PIDOF, SRCMSTR])[0]
    except util.ProcessExecutionError:
        util.logexc(log, 'Failed to get PID of srcmstr process.')
        raise

    srcmstr_pid_before = int(out)
    log.debug('Recycling srcmstr process with PID of %d.' %
              srcmstr_pid_before)
    try:
        os.kill(srcmstr_pid_before, 9)
    except:
        util.logexc(log, 'Failed to kill the srcmstr process.')
        raise

    # wait for srcmstr to come back up
    start_time = time.time()
    while True:
        time.sleep(0.5)
        if time.time() - start_time >= SRCMSTR_TIMEOUT_SECONDS:
            msg = ('srcmstr process failed to come back up within %d seconds.'
                   % SRCMSTR_TIMEOUT_SECONDS)
            log.error(msg)
            raise Exception(msg)
        try:
            new_srcmstr_pid = int(util.subp([PIDOF, SRCMSTR])[0])
            log.debug('srcmstr process came back up with PID of %d.' %
                      new_srcmstr_pid)
            break
        except util.ProcessExecutionError:
            log.debug('Still waiting for srcmstr process to come '
                      'back up...')
            continue
