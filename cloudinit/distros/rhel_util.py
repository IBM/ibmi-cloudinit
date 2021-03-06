# vi: ts=4 expandtab
#
#    Copyright (C) 2012 Canonical Ltd.
#    Copyright (C) 2012, 2013 Hewlett-Packard Development Company, L.P.
#    Copyright (C) 2012 Yahoo! Inc.
#
#    Author: Scott Moser <scott.moser@canonical.com>
#    Author: Juerg Haefliger <juerg.haefliger@hp.com>
#    Author: Joshua Harlow <harlowja@yahoo-inc.com>
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
#

import os
from cloudinit.distros.parsers.resolv_conf import ResolvConf
from cloudinit.distros.parsers.sys_conf import SysConf

from cloudinit import log as logging
from cloudinit import util

LOG = logging.getLogger(__name__)


# Helper function to update a RHEL/SUSE /etc/sysconfig/* file
def update_sysconfig_file(fn, adjustments, allow_empty=False):
    if not adjustments:
        return
    (exists, contents) = read_sysconfig_file(fn)
    updated_am = 0
    for (k, v) in adjustments.items():
        if v is None:
            continue
        v = str(v)
        if len(v) == 0 and not allow_empty:
            continue
        contents[k] = v
        updated_am += 1
    if updated_am:
        lines = [
            str(contents),
        ]
        if not exists:
            lines.insert(0, util.make_header())
        util.write_file(fn, "\n".join(lines) + "\n", 0o644)


# Helper function to read a RHEL/SUSE /etc/sysconfig/* file
def read_sysconfig_file(fn):
    exists = False
    try:
        contents = util.load_file(fn).splitlines()
        exists = True
    except IOError:
        contents = []
    return (exists, SysConf(contents))

# Helper function to write the resolv.conf file, taking into account that the
# file might be immutable before writing, and then making sure it is 
# immutable after writing.  This is done to ensure NetworkManager cannot
# overwrite the file
def write_resolv_conf_file(fn, r_conf):
    util.subp(['chattr', '-i', fn])
    util.write_file(fn, str(r_conf), 0o644)
    util.subp(['chattr', '+i', fn])

# Helper function to write RHEL/SUSE /etc/resolv.conf
def update_resolve_conf_file(fn, dns_servers, search_servers):
    try:
        r_conf = ResolvConf(util.load_file(fn))
        r_conf.parse()
    except IOError:
        util.logexc(LOG, "Failed at parsing %s reverting to an empty "
                    "instance", fn)
        r_conf = ResolvConf('')
        r_conf.parse()
    if dns_servers:
        for s in dns_servers:
            try:
                r_conf.add_nameserver(s)
            except ValueError:
                util.logexc(LOG, "Failed at adding nameserver %s", s)
    if search_servers:
        for s in search_servers:
            try:
                r_conf.add_search_domain(s)
            except ValueError:
                util.logexc(LOG, "Failed at adding search domain %s", s)
    write_resolv_conf_file(fn, r_conf)


# Overwrite the existing conf file so the resolv.conf
# is a replacement versus an update to eliminate unwanted
# existing changes from previous capture data
def remove_resolve_conf_file(fn):
    r_conf = ResolvConf('')
    r_conf.parse()
    write_resolv_conf_file(fn, r_conf)


# Helper function to remove ifcfg-eth* files from network script directory.
def remove_ifcfg_files(directory):
    files = os.listdir(directory)
    for f in files:
        if f.startswith("ifcfg-eth"):
            util.del_file(os.path.join(directory, f))
