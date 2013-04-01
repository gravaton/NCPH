#!/usr/local/bin/ruby

require 'rubygems'
require 'optparse'
require 'ostruct'
require 'logger'
require 'packetfu'
require 'ipaddr'
require 'SubnetBlob'
require 'TestArp'
require 'TestPing'

# Setup our output logging
$log = Logger.new(STDOUT)
$log.formatter = proc{ |level, datetime, progname, msg|
	return level.to_s + " -- " + msg.to_s + "\n"
}
class NCHPInterface
	attr_reader :name, :cap, :arptable, :blob, :arpcount
	def initialize(args = {})
		@name = args[:iface]
		@arpcount = 0
		@arptable = Hash.new { |h,k| h[k] = {:sum => 0} }
		@blob = SubnetBlob.new
		@log = args[:log]
		@cap = PacketFu::Capture.new(:iface => @name)
		@cap_thread = Thread.new {
			begin
				@log.info("Beginning packet capture on #{@name}")
				@cap.capture(:filter => 'arp')
			rescue RuntimeError => e
				@log.fatal("Unable to start packet capture!  Are you sure you have permissions?")
				raise e
			end
			@cap.stream.each { |rawpkt|
				pkt = PacketFu::Packet.parse(rawpkt)
				# Drop the packet if it comes from 0.0.0.0
				# Don't store the MAC of a "Seeking?" target because it's always 00:00:00:00:00:00
				if(pkt.arp_daddr_ip != '0.0.0.0' and pkt.arp_opcode == 2)
					@arptable[pkt.arp_daddr_ip][:mac] = pkt.arp_daddr_mac
					@log.debug("Storing #{pkt.arp_daddr_ip}|#{pkt.arp_daddr_mac}")
					# Count how many times we've seen this host searched for - default gateway should be the most sought after
					arptable[pkt.arp_daddr_ip][:sum] += 1
				end
				if(pkt.arp_saddr_ip != '0.0.0.0')
					@arptable[pkt.arp_saddr_ip][:mac] = pkt.arp_saddr_mac
					@log.debug("Storing #{pkt.arp_saddr_ip}|#{pkt.arp_saddr_mac}")
					@log.debug("Packet number #{count} captured. Opcode: #{pkt.arp_opcode}")
				end
				@arpcount = @arpcount + 1
			}
		}
	end
	def checkIP(args={})
        	# Get our interface information
	        # We have to use our own function for this here because packetfu doesn't support FreeBSD
	        case RUBY_PLATFORM
	        when /freebsd/i
	                ifconfig = BSDifconfig(@name)
	        else
	                ifconfig = PacketFu::Utils.ifconfig(@name)
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
	
	        cap = PacketFu::Capture.new(:iface => @name, :promisc => false)
	        cap.start(:filter => 'arp')
	        3.times do arp.to_w(@name) end
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
	def setIP(args={})
		#This should to the IP setting on the interface fepending on platform
		case RUBY_PLATFORM
		when /freebsd/i
			#We're using FreeBSD
		end
	end
	def checkPing(args={})
	        ping = PacketFu::ICMPPacket.new(:icmp_type => 8, :icmp_code => 0, :body => "This is a ping and a finer ping there has never been 1234567")
	        ping.ip_saddr=args[:src_ip]
	        ping.eth_saddr=args[:src_mac]
	        ping.ip_daddr=args[:dst_ip]
	        ping.eth_daddr=args[:gw_mac]
	        ping.recalc

	        cap = PacketFu::Capture.new(:iface => @name, :promisc => false)
	        fstring = "icmp[icmptype] = icmp-echoreply and src host " + args[:dst_ip]
	        cap.start(:filter => fstring)
	        3.times do ping.to_w(@name) end
	        sleep 5
	        cap.save
	        cap.array.each { |item|
	                pak = PacketFu::Packet.parse(item)
	                return true if pak.payload =~ /This is a ping and a finer ping there has never been 1234567/
	        }
	        return false
	end
end
# Parse the command line options
def doOpts
	# Parse passed-in command line switches
	options = OpenStruct.new
	optparse = OptionParser.new("Usage: NCPH.rb [options] [interface]") { |opts|
		options.debug = false
		options.arpcount = 15
		opts.separator ""
		opts.on( "-aCOUNT", "--arpcount COUNT", Integer, "Number of ARP packets to capture before processing") { |count|
			options.arpcount = count
		}
		opts.on( "-d", "--debug", "Output debug information") { options.debug = true }
		opts.separator ""
		opts.on_tail( "-h", "--help", "Display this screen") {
			puts opts
			exit
		}
		opts.on_tail( "-v", "--version", "Show version") {
			print "NCPH - No Connection Parameters Here\nVersion 0.1\n"
			exit
		}
	}
	optparse.parse!(ARGV)

	# Get our interface
	if ARGV[0] == nil
		$log.fatal("Please specify an interface!")
		exit
	end
	options.tgtif = ARGV[0]
	options
end


options = doOpts()
$log.level = options.debug ? Logger::DEBUG : Logger::INFO

# Open up a non-promiscuous capture on our external interface looking for APRs
begin
	$log.info("Beginning packet capture on #{options.tgtif}")
	cap = PacketFu::Capture.new(:iface => options.tgtif)
	cap.capture(:filter => 'arp')
rescue RuntimeError => e
	$log.fatal("Unable to start packet capture!  Are you sure you have permissions?")
	$log.debug(e.message)
	$log.debug(e.backtrace)
	exit
end

# Set up our tables for the ARPs we see and how often we see them
arptable = Hash.new { |h,k| h[k] = {:sum => 0} }

# We're gonna get the first 15 ARPs we can find
count = 0
while(count < options.arpcount)
	cap.stream.each do |rawpkt|
		pkt = PacketFu::Packet.parse(rawpkt)
		# Drop the packet if it comes from 0.0.0.0
		# Don't store the MAC of a "Seeking?" target because it's always 00:00:00:00:00:00
		if(pkt.arp_daddr_ip != '0.0.0.0' and pkt.arp_opcode == 2)
			arptable[pkt.arp_daddr_ip][:mac] = pkt.arp_daddr_mac unless pkt.arp_opcode == 1
			$log.debug("Storing #{pkt.arp_daddr_ip}|#{pkt.arp_daddr_mac}") unless pkt.arp_opcode == 1
			# Count how many times we've seen this host searched for - default gateway should be the most sought after
			arptable[pkt.arp_daddr_ip][:sum] += 1
		end
		if(pkt.arp_saddr_ip != '0.0.0.0')
			arptable[pkt.arp_saddr_ip][:mac] = pkt.arp_saddr_mac
			$log.debug("Storing #{pkt.arp_saddr_ip}|#{pkt.arp_saddr_mac}")
			count = count + 1
			$log.debug("Packet number #{count} captured. Opcode: #{pkt.arp_opcode}")
		end
		break if count > 15
	end
end

# Just spit it all out for now so we can see what's up
$log.debug("ARP DATABASE")
arptable.each_pair { |key,value|
	$log.debug("#{key}\t#{value[:mac]}\t#{value[:sum]}")
}

# Build a SubnetBlob out of the IPs we've found to actually exist
$log.debug("Building subnet blob...")
blob = SubnetBlob.new((arptable.select { |k,v| v.has_key?(:mac) }).map { |i| i[0] })
$log.debug("Blob contains #{blob.contents.join(' - ')}")
$log.info("Local subnet appears to be #{blob}")

# Pick in IP address for us
newaddr = nil
while newaddr == nil
	newaddr = IPAddr.new(blob.net + rand(blob.mask), Socket::AF_INET)
	$log.info("Testing #{newaddr}")
	if(checkIP(:iface => options.tgtif, :target => newaddr.to_s))
		$log.info("IP #{newaddr} is in use!  Trying again...")
		newaddr = nil
	else
		$log.info("IP #{newaddr} unused!")
	end
end

# Take that address and/or determine what address we're going to use.
# For now let's ask if we want to assign otherwise use our own address.
case RUBY_PLATFORM
when /freebsd/i
	ifdata = BSDifconfig(options.tgtif)
else
	ifdata = PacketFu::Utils.ifconfig(options.tgtif)
end
$log.debug("Interface Data:")
ifdata.each_pair { |a,b|
	$log.debug("#{a} \t-\t#{b}")
}

# Check to see what I've seen ARP-ed for the most

gwcand = arptable.sort { |a,b| b[1][:sum] <=> a[1][:sum] }

# In order from "most arp-ed for" to "least arp-ed for" try to find the default gateway
gwcand.each { |a|
	log.info("Trying #{a[0]}|#{a[1][:mac]} as a potential gateway....")
	if(!a[1].has_key?(:mac))
	   $log.info("Not in database - ARPing for #{a[0]}")
	   haddr = PacketFu::Utils.arp(a[0], iface => ifdata[:iface])
	   if haddr == nil
		   $log.info("Failed.")
		   next
	   end
	   arptable[a[0]][:mac] = haddr
	end
	result = checkPing(:iface => ifdata[:iface], :src_ip => ifdata[:ip_saddr], :src_mac => ifdata[:eth_saddr], :dst_ip => '4.2.2.2', :gw_mac => arptable[a[0]][:mac])
	if result == true
		$log.info("Success!")
		# Set the default gateway
		break
	end
	$log.info("Failed.")
}

