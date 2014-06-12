ISYlogger
=========

Logging tool for the ISY99i/ISY994i from Universal Devices

This tool will connect to a Universal Devices ISY99i or ISY994i and
generate a log of all Insteon traffic. It is capable of logging to
a file, stdout, or to syslog with the appropriate options.

It relies on ISYlib-python, you must install that before using it. 

Requirements:
	ISYlib-python: https://github.com/evilpete/ISYlib-python
	python syslog module
	for daemon support, python daemonize module

usage: ISYlogger.py [-h isyhost] [--ssl[=no]] [-u username] [-p password] [-v|--verbose [...] [--daemon] [--pidfile file] [-l|--logfile file] [-S|--syslog facility.[severity]] [-D|--debug]
        isyhost  - host name of the ISY device
        username - username with admin rights to the ISy
        password - password for the above user
        verbose  - increase verbosity, use multiple times to increase verbosity
                   incresasing this will also add additional message types
        daemon   - run as a daemon
        pidfile  - (implies daemon) file to write process id,
                   default /var/run//var/run/ISYlogger.py.pid
        logfile  - log to the specified file
        syslog   - log to syslog, at the optional facility and severity
                   default daemon.notice
        debug    - enable debugging, if syslog is enabled this will log as debug
                   use multiple times to increase debugging level
                   debug > 1 enable ISY communications debugging

