# -*- ruby -*-
# This file is a part of test scripts of LDAP extension module.

$test = File.dirname($0)
require "#{$test}/conf"
require "./ldap"

case LDAP::LDAP_VENDOR_NAME
when /^OpenLDAP/i
  # false means we use SSL connection.
  conn = LDAP::SSLConn.new($HOST, $SSLPORT, false)
when /^Netscape/i
  conn = LDAP::SSLConn.new($HOST, $SSLPORT,
			   false, File.expand_path("~/.netscape/cert7.db"))
  conn.set_option(LDAP::LDAP_OPT_PROTOCOL_VERSION, 3)
else
  raise(RuntimeError, "unknown vendor")
end

v = conn.get_option(LDAP::LDAP_OPT_PROTOCOL_VERSION)
printf("protocol version = #{v}\n")

conn.bind{
  conn.perror("bind")
}
