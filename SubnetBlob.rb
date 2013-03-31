#!/usr/local/bin/ruby

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
		adr = IPAddr.new(item).to_i
		#adr = IPAddr.new(item)
		@net = adr if @net == nil
		@mask |= (@net ^ adr)
		@net &= adr
		#@carried = @carried.mask((32 - @mask.to_s(2).length))
		@contents << item
	end
	def addr
		adr = IPAddr.new(self.to_s)
	end
	def to_s
		out = [24, 16, 8, 0].collect {|b| (@net >> b) & 255}.join('.')
		out = out + "/#{32 - @mask.to_s(2).length}"
	end
end

#adyary = [ "192.168.50.202", "192.168.50.200", "192.168.50.201", "192.168.50.210", "192.168.50.220", "192.168.50.254", "192.168.50.190", "192.168.51.100" ]
#thing = SubnetBlob.new

#adyary.each { |item|
#	thing.addIP(item)
#}

#print thing, "\n"

#range = IPAddr.new(thing.to_s)

#10.times do
#	newaddy = IPAddr.new(thing.net + rand(thing.mask), Socket::AF_INET)
#	print "Randomly selected address: #{newaddy}\n"
#	print "Included!\n" if range.include?(newaddy)
#end
