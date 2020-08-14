# vi: ts=4 expandtab
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

import re
import contextlib

from cloudinit.distros.parsers.resolv_conf import ResolvConf

from cloudinit import log as logging
from cloudinit import util

LOG = logging.getLogger(__name__)

# Translate Linux ethernet device name ie. eth0 to AIX form ie. en0
def translate_devname(devname):
    device = re.compile('eth[0-9]+')
    if device.match(devname):
        return devname.replace('th', 'n')
    else:
        return devname

# Call chdev to add route
def add_route(network, route):
    # First, delete the route if it exists on the system
    del_route(network, route)

    # Add the route if there isn't already a default route
    cmd = ['/usr/sbin/chdev', '-l', 'inet0']

    if network == 'ipv4':
        cmd.extend(["-aroute=" + "net,-hopcount,0,,0," + route])
    elif network == 'ipv6':
        cmd.extend(["-arout6=" + "net,-hopcount,0,,,::," + route])

    if get_route(network) is None and len(cmd) > 3:
        util.subp(cmd, capture=False, rcs=[0, 1])

# Call chdev to delete default route
def del_route(network, route):
    # if route exists, delete it
    route_out = get_route(network)
    if route_out is not None:
        cmd = ['/usr/sbin/chdev', '-l', 'inet0']
        if network == 'ipv4' and route == route_out.split(",")[5]:
            cmd.append("-adelroute=\"" + route_out + "\"")
        elif network == 'ipv6' and route == route_out.split(",")[6]:
            cmd.append("-adelrout6=\"" + route_out + "\"")

        if len(cmd) > 3: 
            util.subp(cmd, capture=False, rcs=[0, 1])

# Return the default route
def get_route(network):
    # First, delete the route
    if network == 'ipv4':
        cmd = ['/usr/sbin/lsattr', '-El', 'inet0', '-a', 'route', '-F', 'value']
    elif network == 'ipv6':
        cmd = ['/usr/sbin/lsattr', '-El', 'inet0', '-a', 'rout6', '-F', 'value']
    (out, err) = util.subp(cmd)

    out = out.strip()
    if len(out):
        return out
    else:
        return None

# Enable the autoconf6 daemon in /etc/rc.tcpip
def enable_autoconf6(device_name):
    cmd = ['/usr/sbin/chrctcp', '-c', 'autoconf6', '-f', "interface=" + device_name]
    util.subp(cmd, capture=False)
    start_autoconf6(device_name)

# Disable the autoconf6 daemon in /etc/rc.tcpip
def disable_autoconf6():
    cmd = ['/usr/sbin/chrctcp', '-d', 'autoconf6']
    util.subp(cmd, capture=False)

# Configure the IPv6 network interfaces
def start_autoconf6(device_name):
    if device_name == "any":
        cmd = ['/usr/sbin/autoconf6', '-A']
    else:
        cmd = ['/usr/sbin/autoconf6', '-i', device_name]
    util.subp(cmd, capture=False)

# Enable the ndpd-host daemon in /etc/rc.tcpip and start the service
def enable_ndpd_host():
    cmd = ['/usr/sbin/chrctcp', '-S', '-a', 'ndpd-host']
    util.subp(cmd, capture=False)

# Disable the ndpd-host daemon in /etc/rc.tcpip and stop the daemon
def disable_ndpd_host():
    cmd = ['/usr/sbin/chrctcp', '-S', '-d', 'ndpd-host']
    util.subp(cmd, capture=False)

# Enable the dhcpcd daemon in /etc/rc.tcpip and start the service
def enable_dhcpcd():
    cmd = ['/usr/sbin/chrctcp', '-S', '-a', 'dhcpcd']
    util.subp(cmd, capture=False)

# Disable the dhcpcd daemon in /etc/rc.tcpip and stop the service
def disable_dhcpcd():
    cmd = ['/usr/sbin/chrctcp', '-S', '-d', 'dhcpcd']
    util.subp(cmd, capture=False)

#
# Update the /etc/dhcpcd.ini file with the following from
# the info dictionary
#
# option 1  : Subnet Mask
# option 3  : Routers (ip addresses)
# option 50 : Requested IP Address
#
def update_dhcp(tmpf, interface, info):
    util.append_file(tmpf, "interface %s\n" % interface)
    util.append_file(tmpf, "{\n")
    if info.get('netmask'): util.append_file(tmpf, " option 1  %s\n" % (info.get('netmask')))
    if info.get('gateway'): util.append_file(tmpf, " option 3  %s\n" % (info.get('gateway')))
    if info.get('address'): util.append_file(tmpf, " option 50 %s\n" % (info.get('address')))
    util.append_file(tmpf, "}\n\n")

#
# Parse the /etc/dhcpcd.ini file and update it with network information
# from the info dictionary produce by aix.py -> _write_network()
#
# create = True, create a new /etc/dhcpcd.ini file
#        = False, go to the end and update /etc/dhcpcd.ini
#
def config_dhcp(interface, info, create=True):
    infile = "/etc/dhcpcd.ini"
    eat = 0
    updated = 0

    if interface is not None:
        with open(infile, 'r+') as f, util.tempdir() as tmpd:
            tmpf = "%s/dhcpcd.ini" % tmpd
            for line in f.readlines():
                if create is False:
                    util.append_file(tmpf, line)
                else:
                    if eat == 0 and not line.startswith("interface "):
                        util.append_file(tmpf, line)
                    elif eat == 0 and line.startswith("interface "):
                        eat = 1
                    elif eat == 1 and re.match("{", line.strip()):
                        eat = 2
                    elif eat == 2:
                        update_dhcp(tmpf, interface, info)
                        updated = 1
                        eat = 3
            if create is False:
                update_dhcp(tmpf, interface, info)
            else:
                if updated == 0:
                    update_dhcp(tmpf, interface, info)

            util.copy(tmpf, infile)

# Return the device using the lsdev command output
def find_devs_with(path=None):
    """
    find devices matching given criteria (via lsdev)
    """
    lsdev_cmd = ['/usr/sbin/lsdev']
    options = []
    if path:
        options.append("-Cl")
        options.append(path)
    cmd = lsdev_cmd + options

    (out, _err) = util.subp(cmd)
    entries = []
    for line in out.splitlines():
        line = line.strip().split()[0]
        if line:
            entries.append(line)
    return entries

def mount_cb(device, callback, data=None, rw=False, mtype=None, sync=True):
    """
    Mount the device, call method 'callback' passing the directory
    in which it was mounted, then unmount.  Return whatever 'callback'
    returned.  If data != None, also pass data to callback.
    """
    mounted = mounts()
    with util.tempdir() as tmpd:
        umount = False
        devname="/dev/" + device
        if device in mounted:
            mountpoint = mounted[device]['mountpoint']
        elif devname in mounted:
            mountpoint = mounted[devname]['mountpoint']
        else:
            try:
                mountcmd = ['/usr/sbin/mount']
                mountopts = []
                if rw:
                    mountopts.append('rw')
                else:
                    mountopts.append('ro')
                if sync:
                    # This seems like the safe approach to do
                    # (ie where this is on by default)
                    mountopts.append("sync")
                if mountopts:
                    mountcmd.extend(["-o", ",".join(mountopts)])
                if mtype:
                    mountcmd.extend(['-t', mtype])

                if "/cd" in devname:
                        mountcmd.append('-vcdrfs')
                        mountcmd.append(devname)
                else:
                        mountcmd.append(device)

                mountcmd.append(tmpd)
                util.subp(mountcmd)
                umount = tmpd  # This forces it to be unmounted (when set)
                mountpoint = tmpd
            except (IOError, OSError) as exc:
                raise util.MountFailedError(("Failed mounting %s to %s due to: %s") % (device, tmpd, exc))
        # Be nice and ensure it ends with a slash
        if not mountpoint.endswith("/"):
            mountpoint += "/"

        with unmounter(umount):
            if data is None:
                ret = callback(mountpoint)
            else:
                ret = callback(mountpoint, data)
            return ret

def mounts():
    mounted = {}
    try:
        # Go through mounts to see what is already mounted
        (mountoutput, _err) = util.subp("/usr/sbin/mount")
        mount_locs = mountoutput.splitlines()
        mountre = r'\s+(/dev/[\S]+)\s+(/\S*)\s+(\S+)\s+(\S+ \d+ \d+:\d+) (\S+(,\S+)?)'
        for mpline in mount_locs:
            # AIX: /dev/hd4          524288    142672   73%    10402    38% /
            try:
                m = re.search(mountre, mpline)
                dev = m.group(1)
                mp = m.group(2)
                fstype = m.group(3)
                date = m.group(4)
                opts = m.group(5).split(",")[0]
            except:
                continue
            # If the name of the mount point contains spaces these
            # can be escaped as '\040', so undo that..
            mp = mp.replace("\\040", " ")
            mounted[dev] = {
                'fstype': fstype,
                'mountpoint': mp,
                'opts': opts,
                'date': date,
            }
        print("Fetched %s mounts" % mounted)
    except (IOError, OSError):
        print("Failed fetching mount points")
    return mounted

@contextlib.contextmanager
def unmounter(umount):
    try:
        yield umount
    finally:
        if umount:
            umount_cmd = ["/usr/sbin/umount", umount]
            util.subp(umount_cmd)

# Helper function to write the resolv.conf file
def write_resolv_conf_file(fn, r_conf):
    util.write_file(fn, str(r_conf), 0o644)

# Helper function to write /etc/resolv.conf
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
