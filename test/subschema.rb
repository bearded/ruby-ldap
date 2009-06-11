
$test = File.dirname($0)
require "#{$test}/conf"
require "./ldap"
require "#{$test}/../lib/ldap/schema"

conn = LDAP::Conn.new($HOST, $PORT)
conn.bind{
  schema = conn.schema()
  p schema.must("person")
  p schema.attr("person", "MUST")
  p schema.may("person")
  p schema.attr("person", "MAY")
  p schema.sup("person")
  p schema.attr("person", "SUP")
  schema.each{|key,vals|
    vals.each{|val|
      print("#{key}: #{val}\n")
    }
  }
}
