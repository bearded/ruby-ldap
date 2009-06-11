# -*- ruby -*-
# This file is a part of test scripts of LDAP extension module.

$test = File.dirname($0)
require "#{$test}/conf"
require "./ldap"

LDAP::Conn.new($HOST, $PORT).bind{|conn|
  conn.perror("bind")
  begin
    conn.compare("cn=Takaaki Tateishi, dc=localhost, dc=localdomain",
		 "cn", "Takaaki Tateishi")
  rescue LDAP::ResultError
    exit(0)
  end
  exit(1)
}
