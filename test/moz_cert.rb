#!/usr/bin/ruby

require 'rubygems'
# gem 'ruby-ldap', '~> 0.9.12'
require 'ldap'
require 'optparse'
require 'pp'

options = {
  :host	  => 'localhost',
  :port	  => '389',
  :scope  => 'base',
  :filter => '(objectclass=*)',
  :key_pw => ''
}

optparse = OptionParser.new do |opts|
  opts.on("-P", "--certpath [CERTFILE]", "cert8 path") do |cp|
	options[:cp] = cp
  end

  opts.on("-N", "--certname [CERTNAME]", "certificate name") do |opt|
	options[:cn] = opt
  end

  opts.on("-W", "--keypassword PASSWORD", "key password") do |opt|
	options[:key_pw] = opt
  end

  opts.on("-h", "--host HOST", "server hostname") do |host|
	options[:host] = host
  end

  opts.on("-p", "--port PORT", "server port") do |opt|
	options[:port] = opt
  end

  opts.on("-b", "--base [BASE]", "search base") do |opt|
	options[:base] = opt
  end

  opts.on("-s", "--scope SCOPE", "search scope") do |opt|
	options[:scope] = opt
  end

  opts.on("-f", "--filter FILTER", "search filter") do |opt|
	options[:filter] = opt
  end

  opts.on("-a", "--attributes ATTRS", "attrs to return") do |opt|
	options[:attrs] = opt.split(/ *, */)
  end

  opts.on("--help") do |opt|
	puts opts
	exit 0
  end
end

optparse.parse!

required_keys = [:cp, :cn, :base]
if (required_keys - options.keys).length > 0
  puts "Some options are missing."
  puts optparse
  exit 1
end

options[:scope] = case options[:scope]
when "sub"
  LDAP::LDAP_SCOPE_SUBTREE
when "one"
  LDAP::LDAP_SCOPE_ONELEVEL
else
  LDAP::LDAP_SCOPE_BASE
end

raise ArgumentError.new("cert file's missing") unless (File.exists? options[:cp])

#Signal.trap("INT") { puts("INT"); exit(2); }

# Connect
conn = LDAP::SSLAuthConn.new(options[:host], options[:port].to_i, true, 
			    File.expand_path(options[:cp]), options[:cn], options[:key_pw])
conn.set_option(LDAP::LDAP_OPT_PROTOCOL_VERSION, 3)


# oid = '2.16.840.1.113730.3.4.15' # get bound DN
# bindctls = [LDAP::Control.new(oid, "", false)]
# pass bindctls as argument to bind()

begin
  conn.bind

  results = {}
  conn.search(options[:base], options[:scope], options[:filter], options[:attrs], false, 10) do |entry|
	results[entry.dn] = entry.to_hash
  end

  pp results
rescue LDAP::ResultError => e
  puts "error: #{e.to_s}"
end

exit 0
