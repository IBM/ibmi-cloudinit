from cloudinit import util

from cloudinit.settings import PER_INSTANCE
from cloudinit.settings import PER_ALWAYS
import types
#frequency = PER_INSTANCE
frequency = PER_ALWAYS


def handle(name, cfg, cloud, log, args):
    if len(args) != 0:
        hostname = args[0]
    else:
        #hostname = util.get_cfg_option_str(cfg, "hostname", False)
        meta = cloud.datasource.metadata
	#log.debug("In cc_IBMi_change_system_name.py, meta= %s", meta)
	#log.debug("In cc_IBMi_change_system_name.py, meta =%s whose type is %s", meta,type(meta))
    if  'hostname' in meta:
        hostname = meta['hostname']
		
    log.debug("In cc_IBMi_change_rdbdire.py, hostname =%s", hostname)
    if not hostname:
        log.debug("Skipping module named %s, no 'hostname' specified", name)
        return

    # Let the distro handle updating the rdbdire
    cloud.distro.change_IBMi_rdbdire(hostname)
