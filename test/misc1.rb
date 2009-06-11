# -*- ruby -*-

$test = File.dirname($0)
require "#{$test}/conf"
require "./ldap"

def admin_bind
  @ldap_conn.bind("cn=root, dc=localhost, dc=localdomain", 'secret')
end

#test method goes here

def add_ou(agency)
  #creates an organizational unit and places an agency inside
  begin
    entry = {
      'objectclass' => ['organizationalUnit'],
      'ou'          => [agency]
    }
    admin_bind.add("ou=#{entry['ou'][0]}, dc=localhost, dc=localdomain", entry)
    return(true)
  rescue LDAP::ResultError => error
    return(false)
  end
end

def delete_ou(agency)
  #removes an agency organizational unit
  begin
    admin_bind.delete("ou=#{agency}, dc=localhost, dc=localdomain")
    return(true)
  rescue LDAP::ResultError => error
    return(false)
  end
end

@ldap_conn = LDAP::Conn.new($HOST, $PORT)

p LDAP::VERSION
begin
  (1..1000).each do |count|
    p count
    p add_ou("an_agency")
    p delete_ou("an_agency")
  end
rescue LDAP::Error
  exit(0)
end
exit(1)
