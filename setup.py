#
# This module will help you with IPv4 and Ethernet MAC addresses
#
# Ethernet: EUI('00:11:22:33:44:55')
# IPv4 :    IPAddress('192.168.1.254')
#
# And you can pass them as arguments when constructing table entries
from netaddr import EUI, IPAddress
from ipaddress import ip_address


dp = bfrt.port.port_hdl_info.get(CONN_ID=4, CHNL_ID = 0, print_ents=False).data[b'$DEV_PORT']
bfrt.port.port.add(DEV_PORT=dp, SPEED="BF_SPEED_10G", FEC="BF_FEC_TYP_NONE", AUTO_NEGOTIATION ="PM_AN_FORCE_DISABLE", PORT_ENABLE =True)
dp = bfrt.port.port_hdl_info.get(CONN_ID=20, CHNL_ID = 0, print_ents=False).data[b'$DEV_PORT']
bfrt.port.port.add(DEV_PORT=dp, SPEED="BF_SPEED_40G", FEC="BF_FEC_TYP_NONE", AUTO_NEGOTIATION ="PM_AN_FORCE_DISABLE", PORT_ENABLE =True)
dp = bfrt.port.port_hdl_info.get(CONN_ID=13, CHNL_ID = 0, print_ents=False).data[b'$DEV_PORT']
bfrt.port.port.add(DEV_PORT=dp, SPEED="BF_SPEED_40G", FEC="BF_FEC_TYP_NONE", AUTO_NEGOTIATION ="PM_AN_FORCE_DISABLE", PORT_ENABLE =True)



for qsfp_cage in [33]:
    for lane in range(0,4):
        dp = bfrt.port.port_hdl_info.get(CONN_ID=qsfp_cage, CHNL_ID = lane,
                print_ents=False).data[b'$DEV_PORT']
        bfrt.port.port.add(DEV_PORT=dp, SPEED="BF_SPEED_10G", FEC="BF_FEC_TYP_NONE", AUTO_NEGOTIATION ="PM_AN_FORCE_ENABLE", PORT_ENABLE =True)



p4 = bfrt.in_network_caching.pipe

p4.Ingress.nexthop.add_with_l3_switch(
        nexthop_id=100,
        new_mac_da = 0xB8CEF677D76E,
        new_mac_sa = 0x0000FF0000FE,
        port = 284)

#p4.Ingress.ipv4_host.add_with_set_nexthop(
#        dst_ipv4=ip_address('192.168.1.1'),nexthop=100)

p4.Ingress.nexthop.add_with_l3_switch(
        nexthop_id=101,
        new_mac_da = 0x0C42A14F2F66,
        new_mac_sa = 0xFFFFFF0000FF,
        port = 28)

p4.Ingress.ipv4_host.add_with_set_nexthop(
        dst_ipv4=ip_address('192.168.1.3'),nexthop=101)

p4.Ingress.nexthop.add_with_l3_switch(
        nexthop_id=102,
        new_mac_da = 0x1070FD3906CF,
        new_mac_sa = 0x0000FE0000FE,
        port = 24)

p4.Ingress.ipv4_host.add_with_set_nexthop(
        dst_ipv4=ip_address('192.168.1.2'),nexthop=102)

p4.Ingress.ipv4_lpm.add_with_set_nexthop(
        ip_address('191.168.3.0'),24,100)


# nexthop
nexthop = p4.Ingress.nexthop

nexthop.entry_with_send(nexthop_id=0, port=64).push()
nexthop.entry_with_drop(nexthop_id=1).push

#nexthop.entry_with_l3_switch(
#    nexthop_id=100,
#    new_mac_da=EUI('00:00:01:00:00:01'),
#    new_mac_sa=EUI('00:00:FF:00:00:FE'), port=284).push()

#nexthop.entry_with_l3_switch(
#    nexthop_id=101,
#    new_mac_da=EUI('00:00:02:00:00:01'),
#    new_mac_sa=EUI('00:12:34:56:78:9A'), port=28).push()

# ipv4_host
ipv4_host = p4.Ingress.ipv4_host

ipv4_host.entry_with_set_nexthop(
    dst_ipv4=IPAddress('192.168.1.1'), nexthop=100).push()

ipv4_host.entry_with_set_nexthop(
    dst_ipv4=IPAddress('192.168.1.3'), nexthop=101).push()

ipv4_host.entry_with_set_nexthop(
    dst_ipv4=IPAddress('192.168.1.2'), nexthop=102).push() # Doesn't exist!

# ipv4_lpm
ipv4_lpm = p4.Ingress.ipv4_lpm

ipv4_lpm.entry_with_set_nexthop(
    dst_ipv4=IPAddress('192.168.1.0') , nexthop=0).push()

ipv4_lpm.entry_with_set_nexthop(
    dst_ipv4=IPAddress('192.168.3.0'), nexthop=100).push()

ipv4_lpm.entry_with_set_nexthop(
    dst_ipv4=IPAddress('192.168.5.0'), nexthop=101).push()

ipv4_lpm.entry_with_set_nexthop(
    dst_ipv4=IPAddress('192.168.7.0'), nexthop=100).push()

ipv4_lpm.entry_with_set_nexthop(
    dst_ipv4=IPAddress('192.168.0.0'), nexthop=1).push()

ipv4_lpm.set_default_with_set_nexthop(nexthop=0)

# ipv6_lpm

# Mirror sessions as per ../run_pd_rpc/setup.py
cpu_mirror   = 5
port3_mirror = 7
port5_trunc  = 9

#
# Here we decide what to mirror, based on the ingress port
#
ing_port_acl = p4.Ingress.port_acl

ing_port_acl.entry_with_acl_drop_and_mirror(
    ingress_port=1, ingress_port_mask=0x1FF,
    mirror_session = cpu_mirror).push()
ing_port_acl.entry_with_acl_mirror(
    ingress_port=24, ingress_port_mask=0x1FF,
    mirror_session = cpu_mirror).push()
ing_port_acl.entry_with_acl_mirror(
    ingress_port=284, ingress_port_mask=0x1FF,
    mirror_session = cpu_mirror).push()
ing_port_acl.entry_with_acl_mirror(
    ingress_port=28, ingress_port_mask=0x1FF,
    mirror_session = port3_mirror).push()
ing_port_acl.entry_with_acl_mirror(
    ingress_port=284, ingress_port_mask=0x1FF,
    mirror_session = port3_mirror).push()

#
# Here we choose packet treatment
#
#mirror_dest = p4.Egress.mirror_dest

#mirror_dest.entry_with_just_send(
#    ing_mirrored=1, egr_mirrored=0, mirror_session=port3_mirror).push()

#mirror_dest.entry_with_just_send(
#    ing_mirrored=0, egr_mirrored=1, mirror_session=port3_mirror).push()

#
# Mirror session programming
#
mirror_cfg = bfrt.mirror.cfg

mirror_cfg.entry_with_normal(
    sid=5, direction='BOTH', session_enable=True,
    ucast_egress_port=28, ucast_egress_port_valid=1, max_pkt_len=16384).push()

mirror_cfg.entry_with_normal(
    sid=7, direction='BOTH', session_enable=True,
    ucast_egress_port=28, ucast_egress_port_valid=1, max_pkt_len=16384).push()

mirror_cfg.entry_with_normal(
    sid=9, direction='BOTH', session_enable=True,
    ucast_egress_port=28, ucast_egress_port_valid=1, max_pkt_len=100).push()

# Final programming
print("******************* PROGRAMMING RESULTS *****************")
for t in ["ipv4_host", "ipv4_lpm", "nexthop", "ing_port_acl", "mirror_cfg"]:
    print ("\nTable {}:".format(t))
    exec("{}.dump(table=True)".format(t))


