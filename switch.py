#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

def parse_ethernet_header(data):
    dest_mac = data[0:6]
    src_mac = data[6:12]
    ether_type = (data[12] << 8) + data[13]
    vlan_id = -1
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF
        ether_type = (data[16] << 8) + data[17]
    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def trimitere__BPDU(root_bridge_ID, own_bridge_ID, root_path_cost, interface):

    llc_header = bytes([0x42, 0x42, 0x03])
    bpdu_header = struct.pack('!H', 0x0000) + struct.pack('!B', 0x00) + struct.pack('!B', 0x00)

    bpdu_config = (struct.pack('!B', 0) + root_bridge_ID + struct.pack('!I', root_path_cost) +
                 own_bridge_ID + struct.pack('!H', interface + 1) + struct.pack('!H', 0) + struct.pack('!H', 20 * 256) +
                 struct.pack('!H', 2 * 256) + struct.pack('!H', 15 * 256))

    dest_mac = bytes.fromhex('0180c2000000')
    src_mac = get_switch_mac()
    bpdu = bpdu_header +  bpdu_config
    llc_data = llc_header + bpdu
    ethertype_or_length = struct.pack('!H', len(llc_data))
    frame = dest_mac + src_mac + ethertype_or_length + llc_data
    send_to_link(interface, len(frame), frame)
  

def send_bpdu_every_sec():
    global porturi, own_bridge_ID, root_bridge_ID, vlan_config, stare_porturi, switch_id, root_path_cost
    while True:
        if own_bridge_ID == root_bridge_ID:
            for port in porturi:
                nume_port = get_interface_name(port)
                vlan_info = vlan_config.get(nume_port)
                if vlan_info['type'] == 'trunk':  
                    if stare_porturi[switch_id][nume_port]['stare'] != "BLOCKING":
                        trimitere__BPDU(root_bridge_ID, own_bridge_ID, root_path_cost, port)
        time.sleep(1)

def is_unicast(addr):
    first = int(addr.split(':')[0], 16)
    return (first & 1) == 0

def load_vlan_config(switch_id):
    config_file_name = f"configs/switch{switch_id}.cfg"
    vlan_config = {}
    BID = {}

    with open(config_file_name, 'r') as f:
        lines = f.readlines()

    BID[switch_id] = int(lines[0].strip())
    for line in lines[1:]:
        parts = line.strip().split()
        interface = parts[0]
        vlan_or_t = parts[1]
        if vlan_or_t == 'T':
            vlan_config[interface] = {'type': 'trunk', 'id_vlan': None}
        else:
            vlan_id = int(vlan_or_t)
            vlan_config[interface] = {'type': 'access', 'id_vlan': vlan_id}
    return BID, vlan_config

def trimitere_pachet(vlan_id, interfata_dest, interfata_src_nume, data, length, vlan_config):
    interfata_dest_nume = get_interface_name(interfata_dest)
    src_vlan_info = vlan_config.get(interfata_src_nume)
    dest_vlan_info = vlan_config.get(interfata_dest_nume)
    dest_id_vlan = dest_vlan_info['id_vlan']

    if vlan_id != -1:
        src_id_vlan = vlan_id
    else:
        src_id_vlan = src_vlan_info['id_vlan']

    if dest_vlan_info['type'] == 'trunk' or src_id_vlan == dest_id_vlan:
        if src_vlan_info['type'] == 'access' and dest_vlan_info['type'] == 'trunk':
            vlan_tag = create_vlan_tag(src_id_vlan)
            add_tag = data[:12] + vlan_tag + data[12:]
            send_to_link(interfata_dest, length + 4, add_tag)
        elif src_vlan_info['type'] == 'trunk' and dest_vlan_info['type'] == 'access':
            sterge_tag = data[:12] + data[16:]
            send_to_link(interfata_dest, length - 4, sterge_tag)
        else:
            send_to_link(interfata_dest, length, data)

# Process received BPDUs to handle STP
def receiving_a_BPDU(interface, data, own_bridge_ID, root_bridge_ID, root_path_cost, stare_porturi, switch_id, vlan_config, porturi, root_port):
    llc_data = data[14:]
    bpdu = llc_data[3:]

    flags = bpdu[4]
    root_bridge_id_received = bpdu[5:13]
    root_path_cost_received = struct.unpack('!I', bpdu[13:17])[0]
    bridge_id_received = bpdu[17:25]
    port_id_received = bpdu[25:27]

    if root_bridge_id_received < root_bridge_ID:
        root_bridge_ID = root_bridge_id_received
        root_path_cost = root_path_cost_received + 10
        root_port = interface
        root_port_nume = get_interface_name(root_port)
        nume_interfata1 = get_interface_name(interface)

        for port in stare_porturi[switch_id]:
            if port != root_port_nume:
                port_info = vlan_config.get(port)
                if port_info['type'] == 'trunk':  # Fix: trunk spelling
                    stare_porturi[switch_id][port]['stare'] = "BLOCKING"

        if stare_porturi[switch_id][root_port_nume]['stare'] == "BLOCKING":
            stare_porturi[switch_id][root_port_nume]['stare'] = "LISTENING"

        for port in porturi:
            if port != interface:
                nume_interfata = get_interface_name(port)
                port_info = vlan_config.get(nume_interfata)
                if port_info['type'] == 'trunk':  # Fix: trunk spelling
                    if stare_porturi[switch_id][nume_interfata]['stare'] != "BLOCKING":
                        trimitere__BPDU(root_bridge_ID, own_bridge_ID, root_path_cost, port)
    elif root_bridge_id_received == root_bridge_ID:
        if interface == root_port and root_path_cost_received + 10 < root_path_cost:
            root_path_cost = root_path_cost_received + 10
        elif interface != root_port:
            if root_path_cost < root_path_cost_received:
                if stare_porturi[switch_id][nume_interfata1]['stare'] != "DESIGNATED_PORT":
                    stare_porturi[switch_id][nume_interfata1]['stare'] = "LISTENING"

    elif bridge_id_received == own_bridge_ID:
        stare_porturi[switch_id][nume_interfata1]['stare'] = "BLOCKING"

    if own_bridge_ID == root_bridge_ID:
        for port in stare_porturi[switch_id]:
            stare_porturi[switch_id][port]['stare'] = "DESIGNATED_PORT"

# Main function initialization and looping
def main():
    global porturi, own_bridge_ID, root_bridge_ID, vlan_config, stare_porturi, switch_id, root_path_cost
    switch_id = sys.argv[1]
    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)
    camTable = {}
    porturi = list(interfaces)
    bridge_id, vlan_config = load_vlan_config(switch_id)
    stare_porturi = {}

    for port in porturi:
        interfata_nume = get_interface_name(port)
        interfata_info = vlan_config.get(interfata_nume)
        if switch_id not in stare_porturi:
            stare_porturi[switch_id] = {}
        if interfata_nume not in stare_porturi[switch_id]:
            stare_porturi[switch_id][interfata_nume] = {}
        if interfata_info and interfata_info['type'] == 'trunk':
            stare_porturi[switch_id][interfata_nume]['stare'] = 'BLOCKING'

    own_mac = get_switch_mac()
    own_bridge_ID = struct.pack('!H6s', bridge_id[switch_id], own_mac)
    root_bridge_ID = own_bridge_ID
    root_path_cost = 0
    root_port = None

    if own_bridge_ID == root_bridge_ID:
        for port in stare_porturi[switch_id]:
            stare_porturi[switch_id][port]['stare'] = 'DESIGNATED_PORT'

    t = threading.Thread(target=send_bpdu_every_sec)
    t.daemon = True
    t.start()

    while True:
        interface, data, length = recv_from_any_link()
        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)
        
        # Process BPDU frames
        if dest_mac == '01:80:c2:00:00:00':
            receiving_a_BPDU(interface, data, own_bridge_ID, root_bridge_ID, root_path_cost, stare_porturi, switch_id, vlan_config, porturi, root_port)
            continue

        camTable[src_mac] = interface
        interfata_src_nume = get_interface_name(interface)
        # Flooding and unicast handling
        if is_unicast(dest_mac):
            if dest_mac in camTable:
                interfata_dest = camTable[dest_mac]
                nume_interfata = get_interface_name(interfata_dest)
                if stare_porturi[switch_id][nume_interfata]['stare'] != "BLOCKING":
                    trimitere_pachet(vlan_id, interfata_dest, interfata_src_nume, data, length, vlan_config)
            else:
                for o in porturi:
                    if o != interface:
                        nume_interfata = get_interface_name(o)
                        if stare_porturi[switch_id][nume_interfata]['stare'] != "BLOCKING":
                            trimitere_pachet(vlan_id, o, interfata_src_nume, data, length, vlan_config)
        else:
            for o in porturi:
                if o != interface:
                    nume_interfata = get_interface_name(o)
                    if stare_porturi[switch_id][nume_interfata]['stare'] != "BLOCKING":
                        trimitere_pachet(vlan_id, o, interfata_src_nume, data, length, vlan_config)

if __name__ == "__main__":
    main()