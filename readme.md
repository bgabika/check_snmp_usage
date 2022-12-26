
# check_snmp_usage

COREX SNMP free-total-used resource check plugin for Icinga 2
 
### Features
 - checks storage, memory or similar resource usage. Plugin needs exactly 2 oids of 3 (free, used or total) oids
 - prints performance data for Icinga 2 Graphite Module ( and other solutions like Graphite )
 - warning/critical thresholds
 - for more details run check_snmp_usage.py --help

### Usage

<pre><code>
# cd /usr/lib/nagios/plugins
# ./check_snmp_usage.py --hostname myrouter.mydomain.com --used-oid .1.3.6.1.4.1.9.9.109.1.1.1.1.12.7 --free-oid .1.3.6.1.4.1.9.9.109.1.1.1.1.13.7 --warning 80 --critical 90
OK - Resource usage is 51.6% (2080860/4033000). |usage=51.6%;80;90;0;100

</code></pre>


### Version

 - 1.0

### ToDo

 - waiting for bugs or feature requests (-:

## Changelog

 - [initial release] version 1.0

