# -*- ruby -*-
# This file is a part of test scripts of LDAP extension module.

$test = File.dirname($0)
require "#{$test}/conf"
require "./ldap"

sorter = proc{|s1,s2|
  print("sorter: #{s1} <=> #{s2}\n")
  s1<=>s2
}

LDAP::Conn.new($HOST, $PORT).bind{|conn|
  conn.perror("bind")
  sub = nil
  conn.search("dc=localhost, dc=localdomain", LDAP::LDAP_SCOPE_SUBTREE,
	      "(objectclass=*)", nil, false, 0, 0, "sn", sorter){|e|
    dn = e.dn
    print("# #{LDAP.dn2ufn(dn)}\n")
    print("dn: #{dn}\n")
    e.attrs.each{|attr|
      print("#{attr}: #{e.vals(attr).join(', ')}\n")
    }
    print("\n")
    sub = e if !sub
  }

  begin
    sub.dn
  rescue LDAP::InvalidEntryError => e
    $stderr.print("#{e.to_s}.\n",
		  "This exception is expected.\n")
  end
}
