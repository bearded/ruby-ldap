# -*- ruby -*-
# This file is a part of test scripts of LDAP extension module.

$test = File.dirname($0)
require "#{$test}/conf"
require "./ldap"

conn = LDAP::Conn.new($HOST, $PORT)
conn.bind('cn=root, dc=localhost, dc=localdomain','secret'){
  conn.perror("bind")
  conn.delete("cn=Takaaki-Tateishi, dc=localhost, dc=localdomain")
  conn.perror("delete")
}
