from subprocess import Popen, PIPE
import subprocess
import sys
from time import sleep
import logging
from os.path import exists
import re

#################################s
#                               #
# @author: Pradeep CH           #
#                               #
#################################

#Constant variables
NEW_LINE = '\n'
FIREWALL_LOG_FILE = "firewallLogFile"
CHECK_INTERVAL = "interval"
DEFAULT_INTERVAL = 2#sec

class FireWallMonitor(object):
    def __init__(self, logFilePath):
        self.logFile = logFilePath
        self._grepCommand ='grep' #
        #self._grepCommand = 'findstr'
        self._grepkeyword = 'Firewall' 
        
    def getIps(self):
        cmd = [self._grepCommand, self._grepkeyword, self.logFile]
        ips =[]
        op = subprocess.run(cmd,stdout=subprocess.PIPE)
        result = op.stdout.decode('utf-8')
        lines = result.split(NEW_LINE)
        # Read through each result lines
        for line in lines:
            # extract ip
            match= re.search(r"SRC=([.0-9]+).*SYN", line)
            if match:
                ips.append(match.group(1))
        return ips

class IPBlocker(object):
    def __init__(self):
        pass

    def blockIP(self, ip):
        try:
            cmd = ["csf", "-d", ip]
            logging.debug(f"Executomg command : {cmd}" )   
            op = subprocess.run(cmd,stdout=subprocess.PIPE)
            response = op.stdout.decode('utf-8')
            logging.info(f"Blocked ip :{ip} with command response {response}")
            return True
        except:
            logging.error(f"Could not block ip: {ip}")
        return True

class Scheduler(object):
    def __init__(self,durationInSec, firewallMonitor, ipBlocker) :
        self.firewallMonitor = firewallMonitor
        self.ipBlocker =  ipBlocker
        self.durationInSec= durationInSec
        self.blockedIps = []
        self.blockIPListFileName='BlockedIPs'
        self._init()

    def start(self):
        logging.info("Scheduer started....")
        try:
            while True:
                ips = self.firewallMonitor.getIps()
                ipsToBlock = self._ignoreBlockedIPs(ips)
                if len(ipsToBlock)>0:
                    for ip in ipsToBlock:
                        blocked = self.ipBlocker.blockIP(ip)
                        if not blocked:
                            continue
                        self._addToBlockList(ip)
                sleep(self.durationInSec)
        except Exception as ex:
            logging.error(f"The scheduler stopped with cause {ex}")
            logging.exception(ex)

    def _ignoreBlockedIPs(self,ips):
        return [ip for ip in ips if ip not in self.blockedIps] 

    def _addToBlockList(self, ip):
        self.blockedIps.append(ip)
        with open(self.blockIPListFileName, 'a' ) as fp:
            fp.writelines(f"{ip}{NEW_LINE}")

    def _init(self):
        logging.debug("Looking for previously blocked entries...")
        if not exists(self.blockIPListFileName):
            logging.debug("Creating the blocked list file...")
            with open(self.blockIPListFileName,'w') as fp:
                pass
        with open(self.blockIPListFileName, 'r') as fp:
            lines = [line.rstrip() for line in fp]
            for line in lines:
                self.blockedIps.append(line)
        logging.info(f"Number of IPs identfiied as blocked : {len(self.blockedIps)}")


#This class contains basic utility functions
class CommonUtils(object):
    @staticmethod
    def initLogging(logFile, level):
        #logging.basicConfig(filename=logFile, filemode='w', format='%(name)s - %(levelname)s - %(message)s');
        loggingLevel = logging.INFO;
        if(level=='DEBUG'):
            loggingLevel = logging.DEBUG;
        logging.basicConfig(filename=logFile, level=loggingLevel,format='%(asctime)s %(levelname)s %(message)s');
        #logging.basicConfig(level=logging.DEBUG

    @staticmethod
    def processArgs(argv):
        if not argv or len(argv)<2:
            raise Exception("Firewall log file should be specified") 
        args = {}
        args[FIREWALL_LOG_FILE] = argv[1]
        args[CHECK_INTERVAL] = DEFAULT_INTERVAL
        if(len(argv) > 2):
            args[CHECK_INTERVAL] = int(argv[2])
        return args
    
if __name__=='__main__':
    CommonUtils.initLogging("AutoBlocker.log",'DEBUG')
    args = CommonUtils.processArgs(sys.argv)
    firewallMonitor = FireWallMonitor(args[FIREWALL_LOG_FILE])
    ipBlocker = IPBlocker()
    scheduler =  Scheduler(args[CHECK_INTERVAL], firewallMonitor, ipBlocker )
    scheduler.start()
