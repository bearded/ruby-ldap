# -*- ruby -*-
# This file is a part of test scripts of LDAP extension module.

$test = File.dirname($0)
require "#{$test}/conf"
require "./ldap"

$KCODE = "UTF8"

conn = LDAP::Conn.new($HOST, $PORT)
conn.perror("bind")
conn.bind{
  # search2 returns an array of hash
  print("search2 without a block:\n")
  conn.search2("dc=localhost, dc=localdomain", LDAP::LDAP_SCOPE_SUBTREE,
	       "(objectclass=*)", nil, false, 0, 0).each{|ent|
    ent.each{|attr,vals|
      print("#{attr}: #{vals.join(', ')}\n")
    }
    print("\n")
  }
  GC.start()
}
