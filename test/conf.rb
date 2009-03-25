# -*- ruby -*-

require './ldap'

$HOST = 'localhost'
begin
  $PORT = ARGV[0].to_i || LDAP::LDAP_PORT
  $SSLPORT = ARGV[1].to_i || LDAP::LDAPS_PORT
rescue
  $PORT = LDAP::LDAP_PORT
  $SSLPORT = LDAP::LDAPS_PORT
end
