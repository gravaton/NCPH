#!/usr/local/bin/ruby

require 'rubygems'
require 'optparse'
require 'ostruct'
require 'logger'
require 'packetfu'
require 'ipaddr'

class SubnetBlob
        attr_reader :net, :mask, :contents
        def initialize(adrlist = [])
                @mask = 0
                @net = nil
                @contents = []
                adrlist.each { |item|
                        self.addIP(item)
                }
        end
        def addIP(item)
		item = IPAddr.new(item) unless item.kind_of?(IPAddr)
		@net = item if @net == nil
                @mask |= (@net.to_i ^ item.to_i)
                @net = (@net & item).mask(32 - @mask.to_s(2).length)
                @contents << item
        end
	def getIP
		return nil if @net == nil
		begin
		newaddr = IPAddr.new(@net.to_i + rand(@mask), Socket::AF_INET)
		end until not @contents.include?(newaddr)
		@contents << newaddr
		return newaddr
	end
        def IPaddr
                adr = IPAddr.new(self.to_s)
        end
        def to_s
		return "" if @net == nil
		return @net.to_s + "/" + (32 - @mask.to_s(2).length).to_s
        end
end

class NCHPInterface
	attr_reader :name, :cap, :arptable, :blob, :arpcount, :ifcfg
	def initialize(args = {})
		@name = args[:iface]
		@arpcount = 0
		@arptable = Hash.new { |h,k| h[k] = {:sum => 0} }
		@blob = SubnetBlob.new
		@log = args[:log]
		@cap = PacketFu::Capture.new(:iface => @name)
		@ifcfg = self.getIfcfg
		self.startArpCap(:maxarp => args[:maxarp])
	end
	def getIfcfg
		case RUBY_PLATFORM
		when /freebsd/i
			ifdata = BSDifconfig(@name)
		else
			ifdata = PacketFu::Utils.ifconfig(@name)
		end
		@log.debug("Interface Data:")
		ifdata.each_pair { |a,b|
			@log.debug("#{a} \t-\t#{b}")
		}
		return ifdata
	end
	def startArpCap(args = {})
		@cap_thread = Thread.new {
			@log.debug("ARP capture thread starting up on #{@name}")
			begin
				@log.info("Beginning packet capture on #{@name}")
				@cap.capture(:filter => 'arp and not net 169.254.0.0/16')
			rescue RuntimeError => e
				@log.fatal("Unable to start packet capture!  Are you sure you have permissions?")
				raise e
			end
			@cap.stream.each { |rawpkt|
				@log.debug("ARP packet seen")
				pkt = PacketFu::Packet.parse(rawpkt)
				@log.debug(pkt.peek)
				# Drop the packet if it comes from 0.0.0.0
				# Don't store the MAC of a "Seeking?" target because it's always 00:00:00:00:00:00
				if(pkt.arp_daddr_ip != '0.0.0.0' and pkt.arp_opcode == 2)
					@arptable[pkt.arp_daddr_ip][:mac] = pkt.arp_daddr_mac
					@log.debug("Storing #{pkt.arp_daddr_ip}|#{pkt.arp_daddr_mac}")
					@blob.addIP(pkt.arp_daddr_ip)
					@log.debug("Blobbing #{pkt.arp_daddr_ip}")
					# Count how many times we've seen this host searched for - default gateway should be the most sought after
					@arptable[pkt.arp_daddr_ip][:sum] += 1
				end
				if(pkt.arp_saddr_ip != '0.0.0.0')
					@arptable[pkt.arp_saddr_ip][:mac] = pkt.arp_saddr_mac
					@log.debug("Storing #{pkt.arp_saddr_ip}|#{pkt.arp_saddr_mac}")
					@blob.addIP(pkt.arp_saddr_ip)
					@log.debug("Blobbing #{pkt.arp_saddr_ip}")
				end
				@arpcount = @arpcount + 1
				@log.debug("Total number of captured packets: #{@arpcount}")
				break if @arpcount >= args[:maxarp]
			}
			@log.debug("ARP capture thread shutting down on #{args[:iface]}")
			# Clean up the capture
			@cap.clear(:array => true, :stream => true)
			@arpcount
		}
	end
	def checkArpCap
		begin
			return (@cap_thread.alive? ? @arpcount : @cap_thread.value)
		rescue => e
			@log.fatal("Serious error in the capture thread")
			raise e
		end
	end
	def getIP
		newaddr = nil
		while newaddr == nil
			newaddr = @blob.getIP
			#newaddr = IPAddr.new(iface.blob.net.to_i + rand(iface.blob.mask), Socket::AF_INET)
			@log.info("Testing #{newaddr}")
			if(self.checkIP(:target => newaddr.to_s))
				@log.info("IP #{newaddr} is in use!  Trying again...")
				newaddr = nil
			else
				@log.info("IP #{newaddr} unused!")
			end
		end
		return newaddr
	end
	def getGW
		gwcand = @arptable.sort { |a,b| b[1][:sum] <=> a[1][:sum] }
		# In order from "most arp-ed for" to "least arp-ed for" try to find the default gateway
		gwcand.each { |a|
			@log.info("Trying #{a[0]}|#{a[1][:mac]} as a potential gateway....")
			if(!a[1].has_key?(:mac))
			   @log.info("Not in database - ARPing for #{a[0]}")
			   haddr = PacketFu::Utils.arp(a[0], :iface => @name)
			   if haddr == nil
				   @log.info("Failed.")
				   next
			   end
			   iface.arptable[a[0]][:mac] = haddr
			end
			result = self.checkPing(:dst_ip => '4.2.2.2', :gw_mac => @arptable[a[0]][:mac])
			if result == true
				@log.info("Success!")
				return a[0]
			end
			@log.info("Failed.")
		}
		return nil
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
	
	        @cap.capture(:filter => 'arp')
	        3.times do arp.to_w(@name) end
	        sleep 5
	        @cap.save
	        @cap.array.each { |item|
	                pak = PacketFu::Packet.parse(item)
	                next unless pak.arp_opcode == 2 # We only care about responses
	                if pak.arp_saddr_ip == args[:target]
				@cap.clear(:array => true, :stream => true)
	                        return true # The IP is in use if we got a reply from that source IP
	                end
	        }
		@cap.clear(:array => true, :stream => true)
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
	        ping.ip_saddr=@ifcfg[:ip_saddr]
	        ping.eth_saddr=@ifcfg[:eth_saddr]
	        ping.ip_daddr=args[:dst_ip]
	        ping.eth_daddr=args[:gw_mac]
	        ping.recalc

	        fstring = "icmp[icmptype] = icmp-echoreply and src host " + args[:dst_ip]
	        @cap.capture(:filter => fstring)
	        3.times do ping.to_w(@name) end
	        sleep 5
	        @cap.save
	        @cap.array.each { |item|
	                pak = PacketFu::Packet.parse(item)
	                if pak.payload =~ /This is a ping and a finer ping there has never been 1234567/
				@cap.clear(:array => true, :stream => true)
				return true
			end
	        }
		@cap.clear(:array => true, :stream => true)
	        return false
	end
end

# ifconfig stuff for BSD
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

# Parse the command line options
def doOpts
	options = OpenStruct.new
	optparse = OptionParser.new("Usage: NCPH.rb [options] [interface]") { |opts|
		options.debug = false
		options.findip = false
		options.setip = false
		options.gateway = false
		options.maxarp = 15
		opts.separator ""
		opts.on( "-aCOUNT", "--arpcount COUNT", Integer, "Number of ARP packets to capture before processing") { |count|
			options.maxarp = count
		}
		opts.on( "-f", "--findip", "Choose a random IP from the discovered subnet") { options.findip = true }
		opts.on( "-s", "--setip", "Directly set the interface's IP") { options.setip = true }
		opts.on( "-g", "--gateway", "Perform the gateway test on seen IPs") { options.gateway = true }
		opts.separator ""
		opts.on( "-d", "--debug", "Output debug information") { options.debug = true }
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

# Setup our output logging
$log = Logger.new(STDOUT)
$log.formatter = proc{ |level, datetime, progname, msg|
	return level.to_s + " -- " + msg.to_s + "\n"
}

options = doOpts()
$log.level = options.debug ? Logger::DEBUG : Logger::INFO

# OK let's build our interface object and let it listen for ARPs
# Let's even show a nice spinny waiting thing while we do so (if we're not in debug mode)
iface = NCHPInterface.new(:iface => options.tgtif, :log => $log, :maxarp => options.maxarp)
spin = %w[| / - \\]
while iface.checkArpCap < options.maxarp
	unless options.debug 
		iter = 0
		print "Listening for ARPs on #{iface.name} - #{iface.arpcount} of #{options.maxarp} detected....."
		12.times do
			print spin[(iter += 1) % spin.length]
			$stdout.flush
			sleep 0.12
			print "\b"
			$stdout.flush
		end
		print "\r"
	end
end
print "\n"

# Just spit it all out for now so we can see what's up
$log.debug("ARP DATABASE")
iface.arptable.each_pair { |key,value|
	$log.debug("#{key}\t#{value[:mac]}\t#{value[:sum]}")
}

# Print what the network looks like!
$log.info("The network seems to be #{iface.blob}")

# Pick in IP address for us
newaddr = iface.getIP if options.findip

# Take that address and/or determine what address we're going to use.
# For now let's ask if we want to assign otherwise use our own address.
$log.info("SetIP action here") if options.setip

# Check to see what I've seen ARP-ed for the most
gw = iface.getGW if options.gateway
