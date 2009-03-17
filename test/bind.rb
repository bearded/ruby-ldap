# -*- ruby -*-
# This file is a part of test scripts of LDAP extension module.

$test = File.dirname($0)
require "#{$test}/conf"
require "./ldap"

conn = LDAP::Conn.new($HOST, $PORT)
conn.set_option(LDAP::LDAP_OPT_PROTOCOL_VERSION, 3)
conn.bind{
  conn.perror("bind")
  if( defined?(LDAP::LDAP_OPT_HOST_NAME) &&
      defined?(LDAP::LDAP_OPT_PROTOCOL_VERSION) &&
      defined?(LDAP::LDAP_OPT_API_INFO) ) # checking for LDAPv3 API
    host = conn.get_option(LDAP::LDAP_OPT_HOST_NAME)
    proto = conn.get_option(LDAP::LDAP_OPT_PROTOCOL_VERSION)
    begin
      info = conn.get_option(LDAP::LDAP_OPT_API_INFO)
    rescue LDAP::Error
      info = nil
    end
    print("host = #{host}, proto = #{proto}\n",
  	  "info.protocol_version = #{info.protocol_version}\n")
  end
}

begin
  conn.bind
rescue LDAP::InvalidDataError
  $ok = true
end
if( ! $ok )
  raise(RuntimeError, "multiple bind calls")
end
