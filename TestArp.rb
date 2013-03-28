#!/usr/local/bin/ruby

require 'rubygems'
require 'packetfu'

# A FreeBSD ifconfig parser, hopefully to be incorporated into PacketFu
def BSDifconfig(iface='eth0')
	ret = {}
	iface = iface.to_s.scan(/[0-9A-Za-z]/).join # Sanitizing input, no spaces, semicolons, etc.
	ifconfig_data = %x[ifconfig #{iface}]
	if ifconfig_data =~ /#{iface}/
		ifconfig_data = ifconfig_data.split(/[\s]*\n[\s]*/)
	else
		raise ArgumentError, "Cannot ifconfig #{iface}"
	end
	real_iface = ifconfig_data.first
	ret[:iface] = real_iface.split.first.downcase.chomp(":")
	ifconfig_data.each do |s|
		case s
		when /ether[\s]*([0-9a-fA-F:]{17})/
			ret[:eth_saddr] = $1.downcase
			ret[:eth_src] = PacketFu::EthHeader.mac2str(ret[:eth_saddr])
		when /inet[\s]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(.*netmask[\s]*(0x[0-9a-fA-F]{8}))?/
			ret[:ip_saddr] = $1
			ret[:ip_src] = [IPAddr.new($1).to_i].pack("N")
			ret[:ip4_obj] = IPAddr.new($1)
			ret[:ip4_obj] = ret[:ip4_obj].mask(($3.hex.to_s(2) =~ /0*$/)) if $3
		when /inet6[\s]*([0-9a-fA-F:\x2f]+)/
			ret[:ip6_saddr] = $1
			ret[:ip6_obj] = IPAddr.new($1)
		end
	end
	ret
end



def checkIP(args={})

	# Get our interface information
	# We have to use our own function for this here because packetfu doesn't support FreeBSD
	case RUBY_PLATFORM
	when /freebsd/i
		ifconfig = BSDifconfig(args[:iface])
	else
		ifconfig = PacketFu::Utils.ifconfig(args[:iface])
	end

	arp = PacketFu::ARPPacket.new(:flavor => "Linux")
	arp.arp_opcode = 1
	arp.eth_daddr="ff:ff:ff:ff:ff:ff"
	arp.eth_saddr=ifconfig[:eth_saddr]
	arp.arp_saddr_ip="0.0.0.0"
	arp.arp_saddr_mac=ifconfig[:eth_saddr]
	arp.arp_daddr_mac="00:00:00:00:00:00"
	arp.arp_daddr_ip=args[:target]
	arp.recalc

	cap = PacketFu::Capture.new(:iface => args[:iface], :promisc => false)
	cap.start(:filter => 'arp')
	3.times do arp.to_w(args[:iface]) end
	sleep 5
	cap.save
	cap.array.each { |item|
		pak = PacketFu::Packet.parse(item)
		next unless pak.arp_opcode == 2 # We only care about responses
		if pak.arp_saddr_ip == args[:target]
			return true # The IP is in use if we got a reply from that source IP
		end
	}
	return false

end

#BSDifconfig("re0").each_pair { |a,b|
#	print "#{a} \t-\t #{b}\n"
#}
#print checkIP(:iface => "re0", :target => "192.168.1.10") ? "IP Found!\n" : "IP unused!\n"
