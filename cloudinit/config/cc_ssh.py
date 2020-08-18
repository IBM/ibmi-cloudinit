# vi: ts=4 expandtab
#
#    Copyright (C) 2009-2010 Canonical Ltd.
#    Copyright (C) 2012, 2013 Hewlett-Packard Development Company, L.P.
#
#    Author: Scott Moser <scott.moser@canonical.com>
#    Author: Juerg Haefliger <juerg.haefliger@hp.com>
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

import glob
import os

# Ensure this is aliased to a name not 'distros'
# since the module attribute 'distros'
# is a list of distros that are supported, not a sub-module
from cloudinit import distros as ds

from cloudinit import ssh_util
from cloudinit import util
from cloudinit import log as logging
from itoolkit import *
from itoolkit.transport import DatabaseTransport
import ibm_db_dbi as dbi

conn = dbi.connect()
itransport = DatabaseTransport(conn)
#frequency = PER_ALWAYS
LOG = logging.getLogger(__name__)

KEY_DIR_J = "/QOpenSys/QIBM/ProdData/SC1/OpenSSH/openssh-4.7p1/etc/"
KET_DIR_S = "/QOpenSys/QIBM/ProdData/SC1/OpenSSH/etc/"
V_V7R2M0 = "V7R2M0"


KEY_2_FILE = {
    "rsa_private": ("ssh_host_rsa_key", 0o600),
    "rsa_public": ("ssh_host_rsa_key.pub", 0o644),
    "dsa_private": ("ssh_host_dsa_key", 0o600),
    "dsa_public": ("ssh_host_dsa_key.pub", 0o644),
    "ecdsa_private": ("ssh_host_ecdsa_key", 0o600),
    "ecdsa_public": ("ssh_host_ecdsa_key.pub", 0o644),
}

PRIV_2_PUB = {
    'rsa_private': 'rsa_public',
    'dsa_private': 'dsa_public',
    'ecdsa_private': 'ecdsa_public',
}

KEY_GEN_TPL = 'o=$(ssh-keygen -yf "%s") && echo "$o" qsecofr@localhost > "%s"'

GENERATE_KEY_NAMES = ['rsa', 'dsa', 'ecdsa']

KEY_FILE_TPL = 'ssh_host_%s_key'


def handle(_name, cfg, cloud, log, _args):
    
    meta = cloud.datasource.metadata
    if 'mrdb' in meta:
        log.debug("MRDB configuration doesn't need to handle the ssh keys")
        return

    itool = iToolKit(iparm=0, iret=0, ids=1, irow=0)
    itool.add(iCmd('rtvjoba', 'RTVPRDD VRMLVL(?)'))


    # xmlservice
    itool.call(itransport)

    # output
    rtvjoba = itool.dict_out('rtvjoba')

    sys_version = "V7R2M0"

    if 'error' in rtvjoba:
      log.debug(rtvjoba['error'])
    else:
      log.debug(rtvjoba['success'])
      log.debug("VRMLVL is: %s", rtvjoba['VRMLVL'])
      sys_version = rtvjoba['VRMLVL']
    
    if sys_version >= V_V7R2M0:
        ssh_path = KET_DIR_S
    else:
        ssh_path = KEY_DIR_J

    # remove the static keys from the pristine image
    if cfg.get("ssh_deletekeys", True):
        key_pth = os.path.join(ssh_path, "ssh_host_*key*")
        for f in glob.glob(key_pth):
            try:
                util.del_file(f)
            except:
                util.logexc(log, "Failed deleting key file %s", f)

    LOG.debug("cfg is " + str(cfg))
                
    if "ssh_keys" in cfg:
        # if there are keys in cloud-config, use them
        for (key, val) in cfg["ssh_keys"].items():
            if key in KEY_2_FILE:
                tgt_fn = ssh_path + KEY_2_FILE[key][0]
                tgt_perms = KEY_2_FILE[key][1]
                LOG.debug("inserting " + str(val) + " into " + str(tgt_fn))
                util.write_file(tgt_fn, val, tgt_perms)

        for (priv, pub) in PRIV_2_PUB.items():
            if pub in cfg['ssh_keys'] or not priv in cfg['ssh_keys']:
                continue
            pair = (ssh_path + KEY_2_FILE[priv][0], ssh_path + KEY_2_FILE[pub][0])
            cmd = ['sh', '-xc', KEY_GEN_TPL % pair]
            try:
                # TODO(harlowja): Is this guard needed?
                with util.SeLinuxGuard(ssh_path, recursive=True):
                    util.subp(cmd, capture=False)
                log.debug("Generated a key for %s from %s", pair[0], pair[1])
            except:
                util.logexc(log, "Failed generated a key for %s from %s",
                            pair[0], pair[1])
    else:
        # if not, generate them
        genkeys = util.get_cfg_option_list(cfg,
                                           'ssh_genkeytypes',
                                           GENERATE_KEY_NAMES)
        key_file_p = ssh_path + KEY_FILE_TPL
        for keytype in genkeys:
            keyfile = key_file_p % (keytype)
            util.ensure_dir(os.path.dirname(keyfile))
            if not os.path.exists(keyfile):
                cmd = ['ssh-keygen', '-t', keytype, '-N', '', '-f', keyfile]
                try:
                    # TODO(harlowja): Is this guard needed?
                    with util.SeLinuxGuard(ssh_path, recursive=True):
                        util.subp(cmd, capture=False)
                except:
                    util.logexc(log, "Failed generating key type %s to "
                                "file %s", keytype, keyfile)

    try:
        (users, _groups) = ds.normalize_users_groups(cfg, cloud.distro)
        (user, _user_config) = ds.extract_default(users)

        keys = cloud.get_public_ssh_keys() or []
        if "ssh_authorized_keys" in cfg:
            cfgkeys = cfg["ssh_authorized_keys"]
            keys.extend(cfgkeys)

        apply_credentials(keys, user)
    except:
        util.logexc(log, "Applying ssh credentials failed!")


def apply_credentials(keys, user):

    keys = set(keys)
    if user:
        ssh_util.setup_user_keys(keys, user)
