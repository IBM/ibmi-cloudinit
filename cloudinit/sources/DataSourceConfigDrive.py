# vi: ts=4 expandtab
#
#    Copyright (C) 2012 Canonical Ltd.
#    Copyright (C) 2012 Yahoo! Inc.
#
#    Author: Scott Moser <scott.moser@canonical.com>
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

import os

from cloudinit import log as logging
from cloudinit import sources
from cloudinit import util
from cloudinit.distros import aix_util
import platform

from cloudinit.sources.helpers import openstack

LOG = logging.getLogger(__name__)

# Various defaults/constants...
DEFAULT_IID = "iid-dsconfigdrive"
DEFAULT_MODE = 'pass'
DEFAULT_METADATA = {
    "instance-id": DEFAULT_IID,
}
VALID_DSMODES = ("local", "net", "pass", "disabled")
LABEL_TYPES = ('config-2',)
OPTICAL_DEVICES = tuple(('cd%s' % i for i in range(0, 2)))


class DataSourceConfigDrive(openstack.SourceMixin, sources.DataSource):
    def __init__(self, sys_cfg, distro, paths):
        super(DataSourceConfigDrive, self).__init__(sys_cfg, distro, paths)
        self.source = None
        self.dsmode = 'local'
        self.seed_dir = os.path.join(paths.seed_dir, 'config_drive')
        self.version = None
        self.ec2_metadata = None
        self.files = {}

    def __str__(self):
        root = sources.DataSource.__str__(self)
        mstr = "%s [%s,ver=%s]" % (root, self.dsmode, self.version)
        mstr += "[source=%s]" % (self.source)
        return mstr

    def get_data(self):
        found = None
        md = {}
        results = {}
        if os.path.isdir(self.seed_dir):
            try:
                results = read_config_drive(self.seed_dir)
                found = self.seed_dir
            except openstack.NonReadable:
                util.logexc(LOG, "Failed reading config drive from %s",
                            self.seed_dir)
        else:
            util.logexc(LOG, "The seed directory %s not exists",self.seed_dir)

        if (platform.system() == "OS400") and not found :
            if os.path.isdir("/QOPT/CONFIG-2/openstack"):
                try:
                    results = read_config_drive("/QOPT/CONFIG-2")
                    found = "/QOPT/CONFIG-2"
                except openstack.NonReadable:
                    found = None
                    util.logexc(LOG, "Failed reading config drive from %s on IBM i","/QOPT/CONFIG-2")
            else:
                util.logexc(LOG, "The directory /QOPT/CONFIG-2 not exists")
                # read from the backup directory
                if os.path.isdir("/QOpenSys/pkgs/lib/cloudinit/cloud/CONFIG-2/openstack"):
                    try:
                        util.logexc(LOG, "reading config drive from backup on IBM i")
                        results = read_config_drive("/QOpenSys/pkgs/lib/cloudinit/cloud/CONFIG-2")
                        found = "/QOpenSys/pkgs/lib/cloudinit/cloud/CONFIG-2"
                    except openstack.NonReadable:
                        found = None
                        util.logexc(LOG, "Failed reading config drive from %s on IBM i","/QOpenSys/pkgs/lib/cloudinit/cloud/CONFIG-2")
                else:
                    util.logexc(LOG, "The backup directory %s not exists", "/QOpenSys/pkgs/lib/cloudinit/cloud/CONFIG-2/openstack")
                    found = None
        else:
            if not found:
                for dev in find_candidate_devs():
                    try:
                        results = aix_util.mount_cb(dev, read_config_drive)
                        found = dev
                    except openstack.NonReadable:
                        pass
                    except util.MountFailedError:
                        pass
                    except openstack.BrokenMetadata:
                        util.logexc(LOG, "Broken config drive: %s", dev)
                    if found:
                        break
        if not found:
            return False

        md = results.get('metadata', {})
        md = util.mergemanydict([md, DEFAULT_METADATA])
        user_dsmode = results.get('dsmode', None)
        if user_dsmode not in VALID_DSMODES + (None,):
            LOG.warn("User specified invalid mode: %s", user_dsmode)
            user_dsmode = None

        dsmode = get_ds_mode(cfgdrv_ver=results['version'],
                             ds_cfg=self.ds_cfg.get('dsmode'),
                             user=user_dsmode)

        if dsmode == "disabled":
            # most likely user specified
            return False
        LOG.debug("DataSourceConfigDrive.py get_data results=%s", results)
        # TODO(smoser): fix this, its dirty.
        # we want to do some things (writing files and network config)
        # only on first boot, and even then, we want to do so in the
        # local datasource (so they happen earlier) even if the configured
        # dsmode is 'net' or 'pass'. To do this, we check the previous
        # instance-id
        prev_iid = get_previous_iid(self.paths)
        LOG.debug("DataSourceConfigDrive.py get_data prev_iid=%s", prev_iid)
        cur_iid = md['instance-id']
        LOG.debug("DataSourceConfigDrive.py get_data cur_iid=%s",cur_iid)
        LOG.debug("DataSourceConfigDrive.py get_data dsmode=%s,self.dsmode=%s",dsmode,self.dsmode)

        #Comment out the below line
        if prev_iid != cur_iid and self.dsmode == "local":
            on_first_boot(results, distro=self.distro)
        # dsmode != self.dsmode here if:
        #  * dsmode = "pass",  pass means it should only copy files and then
        #    pass to another datasource
        #  * dsmode = "net" and self.dsmode = "local"
        #    so that user boothooks would be applied with network, the
        #    local datasource just gets out of the way, and lets the net claim
        if dsmode != self.dsmode:
            LOG.debug("%s: not claiming datasource, dsmode=%s", self, dsmode)
            return False

        self.source = found
        self.metadata = md
        self.ec2_metadata = results.get('ec2-metadata')
        self.userdata_raw = results.get('userdata')
        self.version = results['version']
        self.files.update(results.get('files', {}))
        self.vendordata_raw = results.get('vendordata')
        return True


class DataSourceConfigDriveNet(DataSourceConfigDrive):
    def __init__(self, sys_cfg, distro, paths):
        DataSourceConfigDrive.__init__(self, sys_cfg, distro, paths)
        self.dsmode = 'net'


def get_ds_mode(cfgdrv_ver, ds_cfg=None, user=None):
    """Determine what mode should be used.
    valid values are 'pass', 'disabled', 'local', 'net'
    """
    # user passed data trumps everything
    if user is not None:
        return user

    if ds_cfg is not None:
        return ds_cfg

    # at config-drive version 1, the default behavior was pass.  That
    # meant to not use use it as primary data source, but expect a ec2 metadata
    # source. for version 2, we default to 'net', which means
    # the DataSourceConfigDriveNet, would be used.
    #
    # this could change in the future.  If there was definitive metadata
    # that indicated presense of an openstack metadata service, then
    # we could change to 'pass' by default also. The motivation for that
    # would be 'cloud-init query' as the web service could be more dynamic
    if cfgdrv_ver == 1:
        return "pass"
    return "net"


def read_config_drive(source_dir, version="2012-08-10"):
    reader = openstack.ConfigDriveReader(source_dir)
    finders = [
        (reader.read_v2, [], {'version': version}),
        (reader.read_v1, [], {}),
    ]
    excps = []
    for (functor, args, kwargs) in finders:
        try:
            return functor(*args, **kwargs)
        except openstack.NonReadable as e:
            excps.append(e)
    raise excps[-1]


def get_previous_iid(paths):
    # interestingly, for this purpose the "previous" instance-id is the current
    # instance-id.  cloud-init hasn't moved them over yet as this datasource
    # hasn't declared itself found.
    fname = os.path.join(paths.get_cpath('data'), 'instance-id')
    try:
        return util.load_file(fname).rstrip("\n")
    except IOError:
        return None


def on_first_boot(data, distro=None):
    """Performs any first-boot actions using data read from a config-drive."""
    if not isinstance(data, dict):
        raise TypeError("Config-drive data expected to be a dict; not %s"
                        % (type(data)))
    net_conf = data.get("network_config", '')
    md = data.get('metadata', {})
    lhost = md['local-hostname']
    host =  md['hostname']
    LOG.debug("DataSourceConfigDrive.py on_first_boot method local-hostname=%s,hostname=%s",lhost,host)
    LOG.debug("DataSourceConfigDrive.py on_first_boot method type of distro=%s",str(type(distro)))
    LOG.debug("DataSourceConfigDrive.py on_first_boot method type of OS=%s",platform.system())
    if net_conf and distro:
        if (platform.system() == "OS400"):
            # move the systemname change here to avoid the netserver start issue
            distro.change_netserver_name(host)
            if 'mrdb' in md:
                distro.mrdb_configuration(md)
            else:
                distro.apply_IBMi_network(net_conf,host)
        else:
            distro.apply_network(net_conf)
    files = data.get('files', {})
    if files:
        LOG.debug("Writing %s injected files", len(files))
        for (filename, content) in files.iteritems():
            if not filename.startswith(os.sep):
                filename = os.sep + filename
            try:
                util.write_file(filename, content, mode=0o660)
            except IOError:
                util.logexc(LOG, "Failed writing file: %s", filename)


def find_candidate_devs(probe_optical=True):
    """Return a list of devices that may contain the config drive.

    The returned list is sorted by search order where the first item has
    should be searched first (highest priority)

    config drive v1:
       Per documentation, this is "associated as the last available disk on the
       instance", and should be VFAT.
       Currently, we do not restrict search list to "last available disk"

    config drive v2:
       Disk should be:
        * either vfat or iso9660 formated
        * labeled with 'config-2'
    """
    # query optical drive to get it in blkid cache for 2.6 kernels
    by_fstype = []
    if probe_optical:
        for device in OPTICAL_DEVICES:
            try:
                by_fstype.extend(aix_util.find_devs_with(device))
            except util.ProcessExecutionError:
                pass

    # We are looking for a block device
    devices = by_fstype
    return devices


# Used to match classes to dependencies
datasources = [
    (DataSourceConfigDrive, (sources.DEP_FILESYSTEM, )),
    (DataSourceConfigDriveNet, (sources.DEP_FILESYSTEM, sources.DEP_NETWORK)),
]


# Return a list of data sources that match this set of dependencies
def get_datasource_list(depends):
    return sources.list_from_depends(depends, datasources)
