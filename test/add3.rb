# -*- ruby -*-
# This file is a part of test scripts of LDAP extension module.

$test = File.dirname($0)
require "#{$test}/conf"
require "./ldap"

$KCODE = "UTF8"

conn = LDAP::Conn.new($HOST, $PORT)
conn.bind('cn=root, dc=localhost, dc=localdomain','secret'){
  conn.perror("bind")
  entry1 = {
    'objectclass' => ['top', 'person'],
    'cn'          => ['立石 孝彰'],
    'sn'          => ['孝彰'],
  }

  entry2 = {
    'objectclass' => ['top', 'person'],
    'cn'          => ['たていし たかあき'],
    'sn'          => ['たていし','たかあき'],
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
