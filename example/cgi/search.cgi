#!/usr/bin/env ruby
# $Id: search.cgi,v 1.1.1.1 2002/11/06 07:56:34 ttate Exp $

require 'cgi'
require 'ldap'

cgi = CGI.new
ldap_host = cgi['host'][0] || 'localhost'
ldap_port = cgi['port'][0] || LDAP::LDAP_PORT
ldap_base_dn = cgi['base'][0] || ''
ldap_filter  = cgi['filter'][0] || ''
ldap_attrs   = (cgi['attrs'][0] || '').split(",")
if( ! ldap_attrs[0] )
  ldap_attrs = nil
end
max_entries  = 50

def html_tag(attr, val)
  tagged_val = val
  case attr.downcase
  when 'mail'
    tagged_val = "<a href=\"mailto:#{val}\">#{val}</a>"
  when 'telephonenumber','tel','telephone',/phone$/
    tagged_val = "<a href=\"tel:#{val.gsub(/[\(\)\-\s]/,'')}\">#{val}</a>"
  when 'fax'
    tagged_val = "<a href=\"fax:#{val.gsub(/[\(\)\-\s]/,'')}\">#{val}</a>"
  end
  case val.downcase
  when /^http:.+/
    tagged_val = "<a href=\"#{val}\">#{val}</a>"
  end
  tagged_val
end

def print_entry(entry)
  print("<table border=1>\n")
  print("<tr><td>dn</td><td>#{entry.dn}</td></tr>\n")
  entry.attrs.each{|attr|
    entry.vals(attr).each{|val|
      print("<tr><td>#{attr}</td><td>#{html_tag(attr,val)}</td></tr>\n")
    }
  }
  print("</table>\n")
  print("<p>\n")
end


print("Content-Type: text/html\n\n")
print("<html><body>\n")
begin
  ldap_conn = LDAP::Conn.new(ldap_host, ldap_port.to_i)
  ldap_conn.bind{
    i = 0
    ldap_conn.search(ldap_base_dn, LDAP::LDAP_SCOPE_SUBTREE,
		     ldap_filter, ldap_attrs){|entry|
      i += 1
      if( i > max_entries )
	raise(RuntimeError,"too many entries are found.")
      end
      print_entry(entry)
    }
  }
rescue LDAP::ResultError => msg
  print(msg)
rescue Exception => ex
  print(ex)
end
print("</body></html>\n")
