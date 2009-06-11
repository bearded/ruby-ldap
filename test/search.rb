# -*- ruby -*-
# This file is a part of test scripts of LDAP extension module.

$test = File.dirname($0)
require "#{$test}/conf"
require "./ldap"

LDAP::Conn.new($HOST, $PORT).bind{|conn|
  conn.perror("bind")
  begin
    conn.search("dc=localhost, dc=localdomain",
		LDAP::LDAP_SCOPE_SUBTREE,
		"(objectclass=*)"){|e|
      p e.vals("cn")
      p e.to_hash()
    }
  rescue LDAP::ResultError => msg
    $stderr.print(msg)
  end
}
