# -*- ruby -*-
# This file is a part of test scripts of LDAP extension module.

$test = File.dirname($0)
require "#{$test}/conf"
require "./ldap"

conn = LDAP::Conn.new($HOST, $PORT)

begin
  conn.bind('cn=root, dc=localhost, dc=localdomain','seret')
rescue LDAP::ResultError => e
  $stderr.print("#{e.inspect} ... expected.\n")
  conn.bind('cn=root, dc=localhost, dc=localdomain','secret'){
    conn.perror("bind")
    conn.modrdn("cn=Takaaki Tateishi, dc=localhost, dc=localdomain",
		"cn=Takaaki-Tateishi",
		true)
    conn.perror("modrdn")
  }
  exit(0)
end
exit(1)
