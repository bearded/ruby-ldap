# -*- ruby -*-
# This file is a part of test scripts of LDAP extension module.

$test = File.dirname($0)
require "#{$test}/conf"
require "./ldap"

conn = LDAP::Conn.new($HOST, $PORT)
conn.bind('cn=root, dc=localhost, dc=localdomain','secret'){
  conn.perror("bind")
  entry1 = {
    'objectclass' => ['top', 'person'],
    'cn'          => ['Tatsuya Kawai'],
    'sn'          => ['kawai'],
  }

  entry2 = {
    'objectclass' => ['top', 'person'],
    'cn'          => ['Mio Tanaka'],
    'sn'          => ['mit','mio'],
  }

  begin
    conn.add("cn=#{entry1['cn'][0]}, dc=localhost, dc=localdomain", entry1)
    conn.add("cn=#{entry2['cn'][0]}, dc=localhost, dc=localdomain", entry2)
  rescue LDAP::ResultError
    conn.perror("add")
    exit
  end
  conn.perror("add")
}
