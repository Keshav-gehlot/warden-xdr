#!/bin/sh
# Demo endpoint: start syslog + sshd so attacks produce real auth.log lines.
set -e
rsyslogd
/usr/sbin/sshd
exec warden-agent
