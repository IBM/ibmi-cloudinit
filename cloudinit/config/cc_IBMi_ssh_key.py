from cloudinit import util

from cloudinit.settings import PER_INSTANCE

import types
frequency = PER_INSTANCE


def handle(name, cfg, cloud, log, args):
    meta = cloud.datasource.metadata
    
    log.debug("cc_IBMi_ssh_key: extracting ssh public key from data source.....")
    
    if 'public_keys' in meta:
        cloud.distro.insert_ssh_pubkey(meta['public_keys'], cfg) 
    else:    
        log.debug("No ssh public key inserted from data source......")

