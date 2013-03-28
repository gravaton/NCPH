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
	fstring = "icmp[icmptype] = icmp-echoreply and src host " + arg[:dst_ip]
	cap.start(:filter => fstring)
	3.times do ping.to_w(arg[:iface]) end
	sleep 5
	cap.save
	cap.array.each { |item|
		pak = PacketFu::Packet.parse(item)
		return true if pak.payload =~ /This is a ping and a finer ping there has never been 1234567/
	}
	return false
end

#checkPing(:iface => 're1', :src_ip => '173.56.234.57', :src_mac => '00:01:80:7b:d5:53', :dst_ip => '4.2.2.2', :gw_mac => '00:1d:b5:70:19:af')
