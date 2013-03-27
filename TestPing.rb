#!/usr/local/bin/ruby

require 'rubygems'
require 'packetfu'


ping = PacketFu::ICMPPacket.new(:icmp_type => 8, :icmp_code => 0, :body => "This is a ping and a finer ping there has never been 1234567")
ping.ip_saddr="173.56.234.57"
ping.eth_saddr="00:01:80:7b:d5:53"
ping.ip_daddr="8.8.8.8"
ping.eth_daddr="00:1d:b5:70:19:af"
ping.recalc

cap = PacketFu::Capture.new(:iface => 're1', :promisc => false)
cap.start(:filter => 'icmp')
ping.to_w('re1')
sleep 5
cap.save
cap.array.each { |item|
	print PacketFu::Packet.parse(item).peek, "\n"
}
