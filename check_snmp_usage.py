#!/usr/bin/python3
# -*- coding: utf-8 -*-
# ---------------------------------------------------------------
# COREX SNMP free-total-used resource check plugin for Icinga 2
# Copyright (C) 2019-2022, Gabor Borsos <bg@corex.bg>
# 
# v1.0 built on 2022.12.17.
# usage: check_snmp_usage.py --help
#
# For bugs and feature requests mailto bg@corex.bg
# 
# ---------------------------------------------------------------
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# Test it in test environment to stay safe and sensible before 
# using in production!
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
# ---------------------------------------------------------------

import sys

try:
    import argparse
    from enum import Enum
    from pysnmp.hlapi import *
    import textwrap

except ImportError as e:
    print("Missing python module: {}".format(str(e)))
    sys.exit(255)



class CheckState(Enum):
    OK = 0
    WARNING = 1
    CRITICAL = 2
    UNKNOWN = 3



class CheckSNMP:

    def __init__(self):

        self.pluginname = "check_snmp_usage.py"
        self.parse_args()



    def parse_args(self):
        parser = argparse.ArgumentParser(
            prog=self.pluginname, 
            add_help=True, 
            formatter_class=argparse.RawTextHelpFormatter,
            description = textwrap.dedent("""
            PLUGIN DESCRIPTION: COREX SNMP free-total-used resource check plugin for Icinga 2.
            This plugin checks storage, memory or similar resource usage. Plugin needs exactly 2 oids of 3 (free, used or total) oids."""),
            epilog = textwrap.dedent(f"""
            Examples:
            {self.pluginname} --hostname myserver.mydomain.com --snmp-port 161 --community public --used-oid 1.2.3.4.5.6.7 --free-oid 1.4.5.6.7.8"""))

        snmp_connection_opt = parser.add_argument_group('SNMP connection arguments', 'hostname, snmp-port, community')
        snmp_connection_opt.add_argument('--hostname', dest="hostname", type=str, required=True, help="host FQDN or IP")
        snmp_connection_opt.add_argument('--snmp-port', dest="snmp_port", type=int, required=False, help="snmp port, default port: 161", default=161)
        snmp_connection_opt.add_argument('--community', dest="snmp_community", type=str, required=False, help="snmp community, default: public", default="public")

        snmp_opt = parser.add_argument_group('check arguments', 'used-oid, free-oid, total-oid, warning, critical')
        snmp_opt.add_argument('--used-oid', dest='used_oid', type=str, required=False, help="used value oid")
        snmp_opt.add_argument('--free-oid', dest='free_oid', type=str, required=False, help="free value oid")
        snmp_opt.add_argument('--total-oid', dest='total_oid', type=str, required=False, help="total value oid")
        snmp_opt.add_argument('--warning', dest='threshold_warning', required=True, type=int,
                                        help='Warning threshold for check value. It must be lower then critical value.')
        snmp_opt.add_argument('--critical', dest='threshold_critical', required=True ,type=int,
                                        help='Critical threshold for check value. It must be higher then warning value.')

        self.options = parser.parse_args()
        self.check_arguments(parser)



    def check_arguments(self, parser):
        if self.check_thresholds_scale() == False:
            parser.error(f"--warning threshold must be lower then --critical threshold!")

        oid_list = []
        if self.options.used_oid == None:
            oid_list.append(self.options.used_oid)
        if self.options.free_oid == None:
            oid_list.append(self.options.free_oid)
        if self.options.total_oid == None:
            oid_list.append(self.options.total_oid)
        
        if len(oid_list) > 1:
            parser.error(f"At least two oid must be set: used-oid or free-oid or total-oid.")



    def main(self):
        
        used_byte, free_byte, total_byte = self.get_perfdata(self.options.hostname, self.options.snmp_port, self.options.snmp_community)
        self.check_value(used_byte, free_byte, total_byte)
        


    @staticmethod
    def output(state, message):
        prefix = state.name
        message = '{} - {}'.format(prefix, message)

        print(message)
        sys.exit(state.value)



    @staticmethod
    def snmp_walk(hostname, oid, snmp_port, snmp_community):

        for (errorIndication,
            errorStatus,
            errorIndex,
            varBinds) in getCmd(SnmpEngine(),
                                CommunityData(snmp_community),
                                UdpTransportTarget((hostname, snmp_port)),
                                ContextData(),
                                ObjectType(ObjectIdentity(oid)),
                                lookupMib=False,
                                lexicographicMode=False):

            if errorIndication:
                print(errorIndication, file=sys.stderr)
                break

            elif errorStatus:
                print('%s at %s' % (errorStatus.prettyPrint(),
                                    errorIndex and varBinds[int(errorIndex) - 1][0] or '?'), file=sys.stderr)
                break

            else:
                for varBind in varBinds:
                    # print('%s = %s' % varBind)
                    return varBind[-1]



    def check_thresholds_scale(self):
        return(self.options.threshold_warning < self.options.threshold_critical)



    def get_perfdata(self, hostname, snmp_port, snmp_community):
        used_oid = self.options.used_oid
        free_oid = self.options.free_oid
        total_oid = self.options.total_oid
        
        def check_oid_result(input_oid_name, byte_data):
            if not isinstance(byte_data, int):
                self.output(CheckState.WARNING, f"Data error in {input_oid_name} output: '{byte_data}'. Check the right oid!")

        if used_oid != None:
            used_byte = int(self.snmp_walk(hostname, used_oid, snmp_port, snmp_community))
            check_oid_result("used-oid", used_byte)
        else:
            used_byte = None

        if free_oid != None:
            free_byte = int(self.snmp_walk(hostname, free_oid, snmp_port, snmp_community))
            check_oid_result("free-oid", free_byte)
        else:
            free_byte = None

        if total_oid != None:
            total_byte = int(self.snmp_walk(hostname, total_oid, snmp_port, snmp_community))
            check_oid_result("total-oid", total_byte)
        else:
            total_byte = None

        return used_byte, free_byte, total_byte
    


    def check_value(self, used_byte, free_byte, total_byte):

        if total_byte == None:
            total_byte = used_byte + free_byte
            usage = round((used_byte / total_byte)*100,2)
        elif used_byte == None:
            used_byte = total_byte - free_byte
            usage = round((used_byte / total_byte)*100,2)
        elif free_byte == None:
            free_byte = total_byte - used_byte
            usage = round((used_byte / total_byte)*100,2)

        output_message = f"Resource usage is {usage}% ({used_byte}/{total_byte}). |usage={usage}%;{self.options.threshold_warning};{self.options.threshold_critical};0;100"

        if usage >= self.options.threshold_critical:
            self.output(CheckState.CRITICAL, output_message)
        elif self.options.threshold_critical > usage and usage >= self.options.threshold_warning:
            self.output(CheckState.WARNING, output_message)
        else:
            self.output(CheckState.OK, output_message)



check_snmp = CheckSNMP()
check_snmp.main()
