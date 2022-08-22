#!/usr/bin/env python3
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI

from p4_mininet import P4Switch, P4Host
from p4runtime_switch import P4RuntimeSwitch
import p4runtime_lib.simple_controller
import p4runtime_lib.helper
import p4runtime_lib.bmv2
import os
import json
from time import sleep
import sys

class SwitchTopo(Topo):
    def __init__(self, sw_path, log_file, json_path, thrift_port, pcap_dump, hosts, **opts):
        Topo.__init__(self, **opts)
        #Add switch to topo object
        self.addSwitch('s1', sw_path = sw_path, log_file = log_file, json_path = json_path, thrift_port = thrift_port, pcap_dump = pcap_dump)
        
        #Set up hosts and links with the switch
        for host_name in hosts:
            self.addHost(host_name, ip=hosts[host_name]['ip'], mac=hosts[host_name]['mac'])
            self.addLink(host_name, 's1')

class NetworkRunner:
    def __init__(self):
        #Set up path variables for log, pcaps and topology
        cwd = os.getcwd()
        self.logs = os.path.join(cwd, 'logs')
        self.pcaps = os.path.join(cwd, 'pcaps')
        self.compiledP4 = os.path.join(cwd, 'build/basic.json')
        self.switchType = 'simple_switch_grpc'
        self.topology = './topology.json'
        
        self.logfile = self.logs + '/switch.log'
        #Read from topology file
        with open(self.topology, 'r') as file:
            top = json.load(file)
        self.hosts = top['hosts']
        
        self.topo = SwitchTopo(self.switchType, self.logfile, self.compiledP4, 9090, self.pcaps, self.hosts)
        
        self.p4info = p4runtime_lib.helper.P4InfoHelper('./build/basic.p4.p4info.txt')

    def createNetwork(self):
        #Create Mininet and start it
        self.net = Mininet(topo = self.topo, host = P4Host, switch = P4RuntimeSwitch, controller = None)
        self.net.start()
        sleep(1)

        #Run commands from topology file on hosts
        for host_name, host_info in list(self.hosts.items()):
            current_host = self.net.get(host_name)
            if "commands" in host_info:
                for cmd in host_info["commands"]:
                    current_host.cmd(cmd)
        
        #Use P4Runtime to do final config on switch
        switch_object = self.net.get('s1')
        grpc_port = switch_object.grpc_port
        device_id = switch_object.device_id
        runtime_json = 's1-runtime.json'
        with open(runtime_json, 'r') as sw_conf_file:
            outfile = '%s/s1-p4runtime-requests.txt' %(self.logs)
            p4runtime_lib.simple_controller.program_switch(
                    addr='127.0.0.1:%d' % grpc_port,
                    device_id=device_id,
                    sw_conf_file=sw_conf_file,
                    workdir=os.getcwd(),
                    proto_dump_fpath=outfile,
                    runtime_json=runtime_json)

        sleep(1)
        
        #start CLI
        CLI(self.net)
       
       # sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(address='127.0.0.1:%d' % grpc_port, device_id=device_id, proto_dump_file='%s/s1-p4runtime-requests.txt' %(self.logs))
       # for response in sw.ReadCounters(self.p4info.get_counters_id('AttackFlagCount'), 0):
        #    for entity in response.entities:
         #       counter = entity.counter_entry
          #      print("SYNACK to victim:   %d" % (counter.data.packet_count))
        
        self.net.stop()


if __name__ == '__main__':

    network = NetworkRunner()
    network.createNetwork()

