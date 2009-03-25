# -*- ruby -*-

$test = File.dirname($0)
require "#{$test}/conf"
require "./ldap"

def add_ou(agency)
  #creates an organizational unit and places an agency inside
  begin
    entry = {
      'objectclass' => ['organizationalUnit'],
      'ou'          => [agency]
    }
    @ldap_conn.add("ou=#{entry['ou'][0]}, dc=localhost, dc=localdomain", entry)
    return(true)
  rescue LDAP::ResultError => error
    return(false)
  end
end

def delete_ou(agency)
  #removes an agency organizational unit
  begin
    @ldap_conn.delete("ou=#{agency}, dc=localhost, dc=localdomain")
    return(true)
  rescue LDAP::ResultError => error
    return(false)
  end
end

@ldap_conn = LDAP::Conn.new($HOST, $PORT)
@ldap_conn.bind("cn=root, dc=localhost, dc=localdomain", 'secret')

p LDAP::VERSION
(1..100).each do |count|
  p count
  p add_ou("an_agency")
  p delete_ou("an_agency")
  GC.start
end
