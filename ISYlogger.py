#!/usr/bin/python
#
# Log ISY events to syslog
#

__author__ = 'Daniel Rich <drich@employees.org>'
__copyright__ = "Copyright (C) 2014 Daniel Rich"
__license__ = "BSD"
__version__ = "0.1"

import os
import sys
import getopt
import time
import syslog
import signal
from ISY.IsyClass import Isy, log_time_offset
from ISY.IsyEventData import EVENT_CTRL, LOG_USERID, LOG_TYPES
from ISY.IsyEvent import ISYEvent

# Defaults
isy = ''
isyHost = 'isy99i.lapseofthought.com'
isyUser = 'admin'
isyPass = '*vosys'
verbose = 0				# Increments with each -v
isyDebug = False
debug = 0
nodeStatus = dict()	# Tracking for node status
daemon = False
logfile = ''
syslogUse = False
syslogFacility = 'daemon'
syslogFacilities = { 'kern'  : syslog.LOG_KERN,
		     'user'  : syslog.LOG_USER,
		     'mail'  : syslog.LOG_MAIL,
		     'daemon': syslog.LOG_DAEMON,
		     'auth'  : syslog.LOG_AUTH,
		     'syslog': syslog.LOG_SYSLOG,
		     'lpr'   : syslog.LOG_LPR,
		     'news'  : syslog.LOG_NEWS,
		     'uucp'  : syslog.LOG_UUCP,
		     'cron'  : syslog.LOG_CRON,
		     'local0': syslog.LOG_LOCAL0,
		     'local1': syslog.LOG_LOCAL1,
		     'local2': syslog.LOG_LOCAL2,
		     'local3': syslog.LOG_LOCAL3,
		     'local4': syslog.LOG_LOCAL4,
		     'local5': syslog.LOG_LOCAL5,
		     'local6': syslog.LOG_LOCAL6,
		     'local7': syslog.LOG_LOCAL7,
		   }
syslogSeverity = 'notice'
syslogSeverities = { 'emerg'  : syslog.LOG_EMERG,
		     'alert'  : syslog.LOG_ALERT,
		     'crit'   : syslog.LOG_CRIT,
		     'err'    : syslog.LOG_ERR,
		     'error'  : syslog.LOG_ERR,
		     'warning': syslog.LOG_WARNING,
		     'warn'   : syslog.LOG_WARNING,
		     'notice ': syslog.LOG_NOTICE,
		     'info'   : syslog.LOG_INFO,
		     'debug'  : syslog.LOG_DEBUG,
		    }
progname = os.path.basename(sys.argv[0])
pidfile = '/var/run/' + progname + '.pid'

time_const=2208988800;

def usage(message=''):
    print message
    print """usage: """ + progname + """ [-h isyhost] [--ssl[=no]] [-u username] [-p password] [-v|--verbose [...] [--daemon] [--pidfile file] [-l|--logfile file] [-S|--syslog facility.[severity]] [-D|--debug]
	isyhost  - host name of the ISY device
	username - username with admin rights to the ISy
	password - password for the above user
	verbose  - increase verbosity, use multiple times to increase verbosity
		   incresasing this will also add additional message types
	daemon   - run as a daemon
	pidfile  - (implies daemon) file to write process id,
		   default /var/run/""" + pidfile + """
	logfile  - log to the specified file
	syslog   - log to syslog, at the optional facility and severity
		   default """ + syslogFacility + '.' + syslogSeverity + """
	debug    - enable debugging, if syslog is enabled this will log as debug
		   use multiple times to increase debugging level
		   debug > 1 will put the isy messages into debug
"""
    sys.exit(1)

# Log an event to syslog or stdout
def log_event(message=''):
    global logfile, syslogUse, syslogSeverities, syslogSeverity

    ts = time.strftime('%b %e %T')
    if syslogUse:	# log to syslog
	syslog.syslog(syslogSeverities[syslogSeverity], message)
    if logfile:	# log to a file
	try:
	    logfile.write("%s %s\n" % (ts, message))
	    logfile.flush()
	except IOError:
	    print "Writing to logfile %s failed!" % logfile.name
	    sys.exit(1)
    if not syslogUse and not logfile:	# log to stdout
	print "%s %s" % (ts, message)

# Parse an event and send it off to the logger
def parse_event(*arg):
    global isy, verbose

    ddat = arg[0]
    # mydat = arg[1]
    exml = arg[2]

    # Message types to skip logging
    skipEvents = {
	0: ['Trigger', 'Heartbeat', 'System Status', 'System Config Updated', 'Electricity'],
	1: ['Heartbeat', 'System Status', 'System Config Updated'],
	2: []
    }
    statusEvents = ['Status', 'On Level', 'Ramp Rate', 'Humidity', 'UOM', 'Thermostat Mode', 'Heat/Cool State']

#    try:
    # Log message, format based on message type
    control = ddat['control']	# Extract message elements
    node = ddat['node']
    evi = ddat['eventInfo']
    action = ddat['action']
    # Get human-readable event control
    ectrl = EVENT_CTRL.get(control, control)
    if ectrl in skipEvents[verbose]:
	return()

    if node:
	# Track status, ramp level, on level and other data for a node
	# The first one we see is the current level, don't log unless
	# in at least double-verbose mode
	if ectrl in statusEvents and (node not in nodeStatus or control not in nodeStatus[node]):
	    if node not in nodeStatus:
		nodeStatus[node] = {}
	    nodeStatus[node][control] = action
	    if verbose < 2:
		return()

        log_event(build_message(node, control, action, evi))
#	# Get name for node address
#	nodeName = isy._node_get_name(node)
#	nodeName = nodeName[1]
#	if nodeName is not None:	# Node has a name
	    # Format messages based on event type
 #	    if ectrl in ['Status', 'Device On', 'Device Off', 'Device Fast On', 'Device Fast Off', 'On Level', 'Ramp Rate']:
#	    elif ectrl in ['Nodes Updated']:
#		action = updateAction[action]
#	        log_event("\"%s\" (%s) %s : %s %s" % (nodeName, node, ectrl, action, evi))
#	    else:	# Some other control message
#	        log_event("\"%s\" (%s) %s : %s %s" % (nodeName, node, ectrl, action, evi))
#	else:	# node, but no nodename
#	    log_event("%s %s : %s %s" % (node, ectrl, action, evi))

    else:	# No node for this event
	log_event("%s = %s %s" % (ectrl, action, evi))

#    except Exception:
#        #print("Unexpected error:", sys.exc_info()[0])
#        print("Unexpected error:", str(sys.exc_info()))
#        print(ddat)
#        # print data
#    finally:
#        pass

# Build the message from the specified data
def build_message(node='', control='', action='', evi=''):
    global isy

    # Dict for Node update/change actions
    updateAction = {
	"NN": "Node Renamed",
	"NR": "Node Removed",
	"ND": "Node Added",
	"NR": "Node Revised",
	"MV": "Node Moved (into a scene)",
	"CL": "Link Changed (in a scene)",
	"RG": "Removed From Group (scene)",
	"EN": "Enabled",
	"PC": "Parent Changed",
	"PI": "Power Info Changed",
	"DI": "Device ID Changed",
	"DP": "Device Property Changed",
	"GN": "Group Renamed",
	"GR": "Group Removed",
	"GD": "Group Added",
	"FN": "Folder Renamed",
	"FR": "Folder Removed",
	"FD": "Folder Added",
	"NE": "Node Error (Comm. Errors)",
	"CE": "Clear Node Error (Comm. Errors Cleared)",
	"SN": "Discovering Nodes (Linking)",
	"SC": "Node Discovery Complete",
	"WR": "Network Renamed",
	"WH": "Pending Device Operation",
	"WD": "Programming Device",
	"RV": "Node Revised (UPB)",
    }

    if evi is None:		# Clear empty event info for logging
	evi = ''

    ectrl = EVENT_CTRL.get(control, control)

    # Set "is" for status updates with no changes, "changed to" for others
    if node in nodeStatus and control in nodeStatus[node] and nodeStatus[node][control] == action:
        actionWord = 'is'
    else:
        if ectrl in ['Status', 'Device On', 'Device Off', 'Device Fast On', 'Device Fast Off', 'On Level', 'Ramp Rate']:
            actionWord = 'changed to'
        else:
            actionWord = ':'
    # Calculate percentage for some events, for others return raw value
    if ectrl in ['Status', 'On Level', 'Ramp Rate']:
        action = str(int(float(action) / 255.0 * 100.0)) + '%'
    elif ectrl in ['Nodes Updated']:
        action = updateAction[action]

    if node:
	nodeName = isy._node_get_name(node)
	nodeName = nodeName[1]
        if nodeName:
            node = "\"%s\" (%s)" % (nodeName, node)
        # No value for on/off events
        if ectrl in ['Device On', 'Device Off', 'Device Fast On', 'Device Fast Off']:
            return("%s %s" % (node, ectrl))
        else:
            return("%s %s %s %s %s" % (node, ectrl, actionWord, action, evi))
        
        
# On request, dump the current node status
def status_dump(signum, frame):
    global isy

    for node in nodeStatus:
	for control in nodeStatus[node]:
            log_event(build_message(node, control, nodeStatus[node][control]))

# Parse command line opts
try:
    opts,args = getopt.getopt(sys.argv[1:], 'h:u:p:vl:S:D', ['host=', 'user=', 'password=', 'ssl=', 'verbose', 'debug', 'daemon', 'pidfile=', 'logfile=', 'syslog='])
except getopt.GetoptError, err:
    print str(err)
    usage()

for o, a in opts:
    if o in ('-h', '--host'):
	isyHost = a
    elif o in ('-u', '--user'):
	isyUser = a
    elif o in ('-p', '--password'):
	isyPass = a
    elif o in ('--ssl'):
	if a and a == 'no':
	    isySSL = False
	else:
	    isySSL = True
    elif o in ('-v', '--verbose'):
	verbose += 1
    elif o in ('-D', '--debug'):
	debug += 1
	if debug > 1:
	    isyDebug = True
    elif o in ('--daemon'):
	daemon = True
    elif o in ('--pidfile'):
	pidfile = a
	daemon = True
    elif o in ('-l', '--logfile'):
	logfile = a
    elif o in ('-S', '--syslog'):
	syslogUse = True
	if a:
	    try:
		(syslogFacility, syslogSeverity) = a.split('.',2)
	    except:
		syslogFacility = a
    else:
	assert False, 'Unknown option ' + o
	usage()

if not isyHost:
    usage('You must specify the ISY hostname')
if not isyUser:
    usage('You must specify the ISY user name')
if not isyPass:
    usage('You must specify the ISY password')

# Validate syslog config 
if syslogUse:
    if syslogFacility not in syslogFacilities:
	usage('Invalid facility: %s' % syslogFacility)
    if syslogSeverity not in syslogSeverities:
	usage('Invalid facility: %s' % syslogSeverity)

    if debug > 0:
	print "DEBUG: logging to syslog %s.%s" % (syslogFacility, syslogSeverity)

# Open a log file for writing if requested
if logfile:
    if debug:
	print "DEBUG: Opening %s for logging" % logfile

# Main loop for daemonizing
def main():
    global isy, syslogUse, syslogFacility, logfile

    # Setup syslog if requested
    if syslogUse:
        syslog.openlog(logoption=syslog.LOG_PID, facility=syslogFacilities[syslogFacility])

    # Open logfile if requested
    if logfile:
        try:
            logfile = open(logfile, 'ab+')
        except IOError:
            usage('ERROR: Failed to open logfile! %s' % sys.exc_info()[1])

    # Dump status on sigusr1
    signal.signal(signal.SIGUSR1,status_dump)

    isy = Isy(addr=isyHost, userl=isyUser, userp=isyPass, debug=isyDebug)
    server = ISYEvent()
    server.subscribe(addr=isyHost, userl=isyUser, userp=isyPass, debug=isyDebug)
    server.set_process_func(parse_event, "")

    try:
	#print('Use Control-C to exit')
	server.events_loop()   #no return
    except KeyboardInterrupt:
	print('Exiting')

# Validate daemon config and load module
if daemon:
    if not daemon and not logfile:	# Require logfile or syslog
	usage('You must specify either syslog or a logfile to use daemon mode')
    from daemonize import Daemonize
    if debug > 0:
	print "DEBUG: daemonizing (%s)" % pidfile
    try:
        daemon = Daemonize(app=progname, pid=pidfile, action=main)
        daemon.start()
    except:
	raise

main()
