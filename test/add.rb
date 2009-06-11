# -*- ruby -*-
# This file is a part of test scripts of LDAP extension module.

$test = File.dirname($0)
require "#{$test}/conf"
require "./ldap"

conn = LDAP::Conn.new($HOST, $PORT)
conn.bind('cn=root, dc=localhost, dc=localdomain','secret'){
  conn.perror("bind")
  entry1 = [
    LDAP.mod(LDAP::LDAP_MOD_ADD, 'objectclass', ['top', 'domain']),
    LDAP.mod(LDAP::LDAP_MOD_ADD, 'o', ['TTSKY.NET']),
    LDAP.mod(LDAP::LDAP_MOD_ADD, 'dc', ['localhost']),
  ]

  entry2 = [
    LDAP.mod(LDAP::LDAP_MOD_ADD, 'objectclass', ['top', 'person']),
    LDAP.mod(LDAP::LDAP_MOD_ADD, 'cn', ['Takaaki Tateishi']),
    LDAP.mod(LDAP::LDAP_MOD_ADD | LDAP::LDAP_MOD_BVALUES, 'sn', ['ttate','Tateishi', "zero\000zero"]),
  ]

  begin
    conn.add("dc=localhost, dc=localdomain", entry1)
    conn.add("cn=Takaaki Tateishi, dc=localhost, dc=localdomain", entry2)
  rescue LDAP::ResultError
    conn.perror("add")
    exit
  end
  conn.perror("add")
}
