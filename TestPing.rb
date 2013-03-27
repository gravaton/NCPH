#!/usr/local/bin/ruby

require 'rubygems'
require 'packetfu'

def checkPing(arg={})
	ping = PacketFu::ICMPPacket.new(:icmp_type => 8, :icmp_code => 0, :body => "This is a ping and a finer ping there has never been 1234567")
	ping.ip_saddr=arg[:src_ip]
	ping.eth_saddr=arg[:src_mac]
	ping.ip_daddr=arg[:dst_ip]
	ping.eth_daddr=arg[:gw_mac]
	ping.recalc

	cap = PacketFu::Capture.new(:iface => arg[:iface], :promisc => false)
	cap.start(:filter => 'icmp')
	ping.to_w(arg[:iface])
	sleep 5
	cap.save
	cap.array.each { |item|
		print PacketFu::Packet.parse(item).peek, "\n"
	}
end
