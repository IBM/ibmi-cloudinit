from cloudinit import util
from cloudinit import log as logging

from itoolkit import *
from itoolkit.db2.idb2call import *
import ibm_db_dbi as dbi

conn = dbi.connect()
itransport = iDB2Call(conn)

from cloudinit.settings import PER_INSTANCE
from cloudinit.settings import PER_ALWAYS
import types
import sys
frequency = PER_ALWAYS

LOG = logging.getLogger(__name__)

def handle(name, cfg, cloud, log, args):
    disks = cloud.distro.get_option('disks')
    if not disks:
        log.debug("In cc_IBMi_configure_disk.py, disks= %s, skip the disk configuration" % (disks))
        return
    log.debug("In cc_IBMi_configure_disk.py, disks= %s" % (disks))
    names, balances, capacities, varyons = getDetailConfig(disks)
    diskList = getUnconfigureDisk().split()
    configureDisk(names, balances, capacities, varyons, diskList)

def getDetailConfig(disks):
    names = []
    balances = []
    capacities = []
    varyons = []
    i = 0
    for disk in disks:
        if not disks[disk].has_key('name'):
            disks[disk]['name'] = 'AUTOASP' + str(i)
            i = i + 1
        if not disks[disk].has_key('balance'):
            disks[disk]['balance'] = "N"
        if not disks[disk].has_key('capacity'):
            disks[disk]['capacity'] = 0
        if not disks[disk].has_key('varyon'):
            disks[disk]['varyon'] = "Y"
        if not disks[disk].has_key('priority'):
            disks[disk]['priority'] = sys.maxint
    new_disks = sorted(disks.items(), key=lambda obj: obj[1]['priority'])
    for disk in new_disks:
        names.append(disk[1].get('name').upper())
        balances.append(disk[1].get('balance'))
        capacities.append(disk[1].get('capacity'))
        varyons.append(disk[1].get('varyon'))
    return names, balances, capacities, varyons

def configureDisk(names, balances, capacities, varyons, diskList):
    diskLen = len(diskList)
    i = 0
    j=diskLen
    k1 = 0
    flag = False
    while(i<len(capacities) and j > 0):
        k3 = int(round(capacities[i]*diskLen)+k1) if j >= int(round(capacities[i]*diskLen)) else (j+k1)
        k2 = range(k1, k3)
        list = [diskList[n] for n in k2]
        LOG.debug("aspName = %s, balance = %s, diskList = %s, vary-on = %s" % (names[i], balances[i], list, varyons[i]))
        if list:
            isExist = configureASP(names[i], balances[i], list)
            if not isExist:
                addASPDev(names[i])
            varyonASP(names[i], varyons[i])
            doBalance(names[i], balances[i])
        i = i + 1
        k1 = k1 + len(k2)
        j = j - len(k2)

def getUnconfigureDisk():
    itool = iToolKit()
    itool.add(
     iPgm('qyasrdi','QYASRDI')
     .addParm(
      iDS('DMIN0100_t',{'len':'dmilen'})
      .addData(iData('dniRet','10i0',''))
      .addData(iData('dmiAvl','10i0',''))
      .addData(iData('dmiOfset','10i0',''))
      .addData(iData('dmiNbr','10i0','',{'enddo':'mycnt'}))
      .addData(iData('dmiLen','10i0',''))
      .addData(iData('dmiRes','10i0',''))
      .addData(iDS('res_t',{'dim':'999','dou':'mycnt'})
               .addData(iData('resDurn','10a',''))
               .addData(iData('resDuff','1a',''))
               .addData(iData('resTrnaswdu','10a',''))
               .addData(iData('resTnawdu','4a',''))
               .addData(iData('resDuaindpsf','1a',''))
               .addData(iData('resDuaiedpsf','1a',''))
               .addData(iData('resRes','5a',''))
               .addData(iData('resDpsn','10i0',''))
               .addData(iData('resCaadps','10i0',''))
               )
     )
     .addParm(iData('rcvlen','10i0','',{'setlen':'dmilen'}))
     .addParm(iData('fmtnam','10a','DMIN0100'))
     .addParm(iData('dmiDurna','10a','*UNCONFIG'))
     .addParm(iData('dmiNbr','10i0','1'))
     .addParm(
      iDS('ERRC0100_t',{'len':'errlen'})
      .addData(iData('errRet','10i0',''))
      .addData(iData('errAvl','10i0',''))
      .addData(iData('errExp','7A','',{'setlen':'errlen'}))
      .addData(iData('errRsv','1A',''))
     )
    )
    # xmlservice
    itool.call(itransport)
    #output
    qyasrdi = itool.dict_out('qyasrdi')
    diskList = ''
    if 'success' in qyasrdi:
        DMIN0100_t = qyasrdi['DMIN0100_t']
        if int(DMIN0100_t['dmiNbr']) > 0:
            res_t = DMIN0100_t['res_t']
            if int(DMIN0100_t['dmiNbr']) == 1:
                diskList=res_t['resDurn']
            else:
                for rec in res_t:
                    diskList+=rec['resDurn']+' '
        else:
            LOG.debug('There is no un-configured disk unit.')
    else:
        LOG.debug(qyasrdi['error'])
    return diskList

def configureASP(name, balance, diskList):
    isExist = False
    LOG.debug('Read from QSYS2.ASP_INFO to find asp with name: %s' % (name))
    cursor = conn.cursor()
    sql = "SELECT ASP_NUMBER FROM QSYS2.ASP_INFO WHERE RDB_NAME = '" + name + "';"
    asp_number = '000'
    try:
       cursor.execute(sql)
       result = cursor.fetchone()
       if result:
           if result[0] >= 100:
               asp_number = result[0]
           else:
               asp_number = '0' + repr(result[0])
           isExist = True
           LOG.debug('ASP %s is exist, use it ASP_NUMBER %s to configure' % (name, asp_number))
    except:
       LOG.debug('Error: unable to fecth data from ASP_NUMBER')

    cmd_str = "CALL PGM(QSYS/QAENGADDDU) PARM('"
    if name == "SYSBASE":
        cmd_str  = cmd_str + fmtTo10("*SYSBASE") + "' '001' "
    else:
        cmd_str  = cmd_str + fmtTo10(name) + "' '" + asp_number + "' "
    if balance == 'Y':
        cmd_str = cmd_str + "'1' "
    else:
        cmd_str = cmd_str + "'0' "
    for disk in diskList:
        cmd_str = cmd_str + "'" + fmtTo10(disk) + "' "
    cmd_str = cmd_str + ")"
    exeCmd(cmd_str)
    return isExist

def doBalance(name, balance):
    if balance == 'N':
        return
    if name == 'SYSBASE':
        cmd_str = "STRASPBAL TYPE(*CAPACITY) ASP(1) TIMLMT(*NOMAX)"
    else:
        cmd_str = "STRASPBAL TYPE(*CAPACITY) ASPDEV(" + name + ") TIMLMT(*NOMAX)"
    exeCmd(cmd_str)

def addASPDev(name):
    if name == 'SYSBASE':
        LOG.debug("SYSBASE do not need to create devd, just skip it")
    else:
        cmd_str = "CRTDEVASP DEVD(" + name + ") RSRCNAME(" + name + ")"
        exeCmd(cmd_str)

def varyonASP(name, varyon):
    if name == "SYSBASE" or varyon == "N":
        pass
    else:
        cmd_str = "VRYCFG CFGOBJ(" + name + ") CFGTYPE(*DEV) STATUS(*ON)"
        exeCmd(cmd_str)

def fmtTo10(str):
    return str.ljust(10) if len(str) <= 10 else str[0:10]

def exeCmd(cmd_str):
    cmd = ['system', cmd_str]
    log_cmd = ['system', cmd_str]
    try:
        LOG.debug("Run command %s" % (cmd))
        util.subp(cmd, logstring=log_cmd)
    except Exception as e:
        LOG.debug("Fail to run command %s with error %s." % (log_cmd, e))
