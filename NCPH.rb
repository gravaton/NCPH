#!/usr/local/bin/ruby

require 'logger'
require 'rubygems'
require 'packetfu'
require 'ipaddr'
require 'SubnetBlob'
require 'TestArp'
require 'TestPing'

# Setup our output logging

log = Logger.new(STDOUT)
log.level = Logger::DEBUG

# Get our interface
if ARGV[0] == nil
	log.fatal("Please specify an interface!")
	exit
else
	tgtif = ARGV[0]
end

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
		# Drop the packet if it comes from 0.0.0.0
		next if pkt.arp_saddr_ip == '0.0.0.0'
		# Don't store the MAC of a "Seeking?" target because it's always 00:00:00:00:00:00
		arptable[pkt.arp_daddr_ip] = pkt.arp_daddr_mac unless pkt.arp_opcode == 1
		log.debug("Storing #{pkt.arp_daddr_ip}|#{pkt.arp_daddr_mac}") unless pkt.arp_opcode == 1
		# Always store the MAC of the seeker
		arptable[pkt.arp_saddr_ip] = pkt.arp_saddr_mac
		log.debug("Storing #{pkt.arp_saddr_ip}|#{pkt.arp_saddr_mac}")
		# Count how many times we've seen this host searched for - default gateway should be the most sought after
		arpcount[pkt.arp_daddr_ip] += 1
		count = count + 1
		log.debug("Packet number #{count} captured. Opcode: #{pkt.arp_opcode}")
		break if count > 15
	end
end

# Just spit it all out for now so we can see what's up
log.debug("ARP DATABASES\n=============")
arpcount.each_pair { |key,value|
	log.debug("#{key}\t#{value}")
}
arptable.each_pair { |key,value|
	log.debug("#{key}\t#{value}")
}

# Build a SubnetBlob

blob = SubnetBlob.new
arpcount.each_key { |item|
	blob.addIP(item)
}
log.info("I think this subnet is #{blob}")

# Pick in IP address for us

newaddr = IPAddr.new(blob.net + rand(blob.mask), Socket::AF_INET)
log.info("I'm gonna try #{newaddr}")

# See if that address is free

if(checkIP(:iface => tgtif, :target => newaddr.to_s))
	log.info("IP #{newaddr} used!")
else
	log.info("IP #{newaddr} unused!")
end

# Take that address and/or determine what address we're going to use.
# For now let's ask if we want to assign otherwise use our own address.
case RUBY_PLATFORM
when /freebsd/i
	ifdata = BSDifconfig(tgtif)
else
	ifdata = PacketFu::Utils.ifconfig(tgtif)
end
log.debug("IFDATA:")
ifdata.each_pair { |a,b|
	log.debug("#{a} \t-\t#{b}")
}

# Check to see what I've seen ARP-ed for the most

gwcand = arpcount.sort { |a,b| b[1] <=> a[1] }

# In order from "most arp-ed for" to "least arp-ed for" try to find the default gateway
gwcand.each { |a|
	log.info("Trying #{a[0]}|#{arptable[a[0]]} as a potential gateway....")
	if(!arptable.has_key?(a[0]))
	   log.info("Not in database - ARPing for #{a[0]}")
	   haddr = PacketFu::Utils.arp(a[0])
	   if haddr == nil
		   log.info("Failed.")
		   next
	   end
	   arptable[a[0]] = haddr
	end
	result = checkPing(:iface => ifdata[:iface], :src_ip => ifdata[:ip_saddr], :src_mac => ifdata[:eth_saddr], :dst_ip => '4.2.2.2', :gw_mac => arptable[a[0]])
	if result == true
		log.info("Success!")
		# Set the default gateway
		break
	end
	log.info("Failed.")
}

