# $Id: setup.rb,v 1.3 2005/03/13 10:10:56 ianmacd Exp $
#
# Basic set-up for performing LDAP unit tests.

require 'ldap'
require 'ldap/schema'
require 'test/unit'

class TC_LDAPTest < Test::Unit::TestCase

  @@conn = nil

  # Get the LDAP host and base DN from /etc/ldap.conf.
  def setup
    unless @@conn && @@conn.bound?
      File.open( '/etc/ldap.conf' ) do |f|
        while line = f.gets
          if line =~ /^host\s+(\S+)$/
            @@host = $1
            break
	  elsif line =~ /^base\s+(\S+)$/
	    @@base = $1
	    break
          end
        end
      end

      @@conn = LDAP::Conn.new( @@host )
      @@conn.set_option( LDAP::LDAP_OPT_PROTOCOL_VERSION, 3 )
      @@conn.bind
      @@root_dse = @@conn.root_dse[0]
      @@naming_context = @@root_dse['namingContexts'][0]
    end
  end

  undef_method :default_test
    
end
