# -*- ruby -*-
# This file is a part of test scripts of LDAP extension module.

$test = File.dirname($0)
require "#{$test}/conf"
require "./ldap"

cred = "secret"

conn = LDAP::Conn.new($HOST, $PORT)

v = conn.get_option(LDAP::LDAP_OPT_PROTOCOL_VERSION)
printf("protocol version = #{v}\n")

conn.sasl_bind(nil, LDAP::LDAP_SASL_SIMPLE, cred){
  conn.perror("bind")
}
