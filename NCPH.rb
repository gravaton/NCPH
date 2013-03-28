#!/usr/local/bin/ruby

require 'rubygems'
require 'packetfu'
require 'ipaddr'
require 'SubnetBlob'
require 'TestArp'
require 'TestPing'

# Define our interface

tgtif = 're0'

# Open up a non-promiscuous capture on our external interface looking for APRs
# TODO: Make this more useful as to picking an interface, it's hard-coded now and that's silly
cap = PacketFu::Capture.new(:iface => tgtif)
cap.capture(:filter => 'arp')

# Set up our tables for the ARPs we see and how often we see them
arptable = Hash.new
arpcount = Hash.new(0)

# We're gonna get the first 15 ARPs we can find
count = 0
while(count < 15)
	cap.stream.each do |rawpkt|
		pkt = PacketFu::Packet.parse(rawpkt)
		# Don't store the MAC of a "Seeking?" target because it's always 00:00:00:00:00:00
		arptable[pkt.arp_daddr_ip] = pkt.arp_daddr_mac unless pkt.arp_opcode == 1
		# Always store the MAC of the seeker
		arptable[pkt.arp_saddr_ip] = pkt.arp_saddr_mac
		# Count how many times we've seen this host searched for - default gateway should be the most sought after
		arpcount[pkt.arp_daddr_ip] += 1
		count = count + 1
		print "Packet number #{count} captured. Opcode: #{pkt.arp_opcode}\n"
		break if count > 15
	end
end

# Build a SubnetBlob

blob = SubnetBlob.new
arpcount.each_key { |item|
	blob.addIP(item)
}
print "I think this subnet is #{blob}\n"

# Pick in IP address for us

newaddr = IPAddr.new(blob.net + rand(blob.mask), Socket::AF_INET)
print "I'm gonna try #{newaddr}\n"

# See if that address is free

if(checkIP(:iface => tgtif, :target => newaddr.to_s))
	print "IP #{newaddr} used!\n"
else
	print "IP #{newaddr} unused!\n"
end

# Take that address and/or determine what address we're going to use.
# For now let's ask if we want to assign otherwise use our own address.
case RUBY_PLATFORM
when /freebsd/i
	ifdata = BSDifconfig('re0')
else
	ifdata = PacketFu::Util.ifconfig('re0')
end
#
# Check to see what I've seen ARP-ed for the most
gwcand = arpcount.sort { |a,b| b[1] <=> a[1] }
gwcand.each { |a|
	a.each { |b| print b, "\n" }
}

print "IFDATA:\n"
ifdata.each_pair { |a,b|
	print "#{a} \t-\t#{b}\n"
}
# In order from "most arp-ed for" to "least arp-ed for" try to find the default gateway
result = checkPing(:iface => ifdata[:iface], :src_ip => ifdata[:ip_saddr], :src_mac => ifdata[:eth_saddr], :dst_ip => '4.2.2.2', :gw_mac => '00:1d:b5:70:19:af')
if result == true
	print "We did it!\n"
else
	print "Nope!\n"
end
#
# Just spit it all out for now so we can see what's up
arpcount.each_pair { |key,value|
	print key, "\t", value, "\n"
}
arptable.each_pair { |key,value|
	print key, "\t", value, "\n"
}
