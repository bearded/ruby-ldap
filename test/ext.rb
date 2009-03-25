# -*- ruby -*-
# This file is a part of test scripts of LDAP extension module.

$test = File.dirname($0)
require "#{$test}/conf"
require "./ldap"

conn = LDAP::Conn.new($HOST, $PORT)
conn.bind('cn=root, dc=localhost, dc=localdomain','secret'){
  conn.perror("bind")
  begin
    (1..200).each{|i|
      entry = {
	'objectclass' => ['top', 'person'],
	'cn'          => ["User #{i}"],
	'sn'          => ["user#{i}"],
      }
      conn.add("cn=User #{i}, dc=localhost, dc=localdomain", entry)
    }
  rescue LDAP::ResultError
    conn.perror("add")
    exit(1)
  end
  conn.perror("add")

  if( !defined?(conn.search_ext) )
    exit(0)
  end

  users = []
  begin
    conn.search_ext("dc=localhost, dc=localdomain",
		    LDAP::LDAP_SCOPE_SUBTREE,
		    "(&(objectclass=*)(cn=User*))",
		    nil, false,    # attrs, attrsonly
		    nil, nil,      # serverctrls, clientctrls
		    0, 0,          # sec, usec
		    100){|e|       # sizelimit
      users.push(e.vals("sn"))
    }
  rescue LDAP::ResultError
    conn.perror("search_ext")
    if( conn.err == LDAP::LDAP_SIZELIMIT_EXCEEDED )
      exit(0)
    else
      exit(1)
    end
  end
}
