# Manipulation of LDAP schema data.
#
#--
# $Id: schema.rb,v 1.9 2006/02/08 23:15:17 ianmacd Exp $
#++

# The LDAP module encapsulates the various LDAP-related classes in their own
# namespace.
#
module LDAP

  # Retrieve and process information pertaining to LDAP schemas.
  #
  class Schema < Hash

    def initialize(entry)
      if( entry )
	entry.each{|key,vals|
	  self[key] = vals
	}
      end
    end

    # Return the list of values related to the schema component given in
    # +key+. See LDAP::Conn#schema for common values of +key+.
    #
    def names(key)
      self[key].collect{|val| val =~ /NAME\s+'([\w\d_\-]+)'/; $1}
    end

    # Return the list of attributes in object class +oc+ that are of category
    # +at+. +at+ may be the string *MUST*, *MAY* or *SUP*.
    #
    def attr(oc,at)
      self['objectClasses'].each{|s|
	if( s =~ /NAME\s+'#{oc}'/ )
	  case s
	  when /#{at}\s+\(([\w\d_\-\s\$]+)\)/i then return $1.split("$").collect{|attr| attr.strip}
	  when /#{at}\s+([\w\d_\-]+)/i then return $1.split("$").collect{|attr| attr.strip}
	  end
	end
      }
      return nil
    end

    # Return the list of attributes that an entry with object class +oc+
    # _must_ possess.
    #
    def must(oc)
      attr(oc, "MUST")
    end

    # Return the list of attributes that an entry with object class +oc+
    # _may_ possess.
    #
    def may(oc)
      attr(oc, "MAY")
    end

    # Return the superior object class of object class +oc+.
    #
    def sup(oc)
      attr(oc, "SUP")
    end
  end

  class Conn

    # Fetch the schema data for the connection.
    #
    # If +base+ is given, it gives the base DN for the search. +attrs+, if
    # given, is an array of attributes that should be returned from the
    # server. The default list is *objectClasses*, *attributeTypes*,
    # *matchingRules*, *matchingRuleUse*, *dITStructureRules*,
    # *dITContentRules*, *nameForms* and *ldapSyntaxes*.
    #
    # +sec+ and +usec+ can be used to specify a time-out for the search in
    # seconds and microseconds, respectively.
    # 
    def schema(base = nil, attrs = nil, sec = 0, usec = 0)
      attrs ||= [
	'objectClasses',
	'attributeTypes',
	'matchingRules',
	'matchingRuleUse',
	'dITStructureRules',
	'dITContentRules',
	'nameForms',
	'ldapSyntaxes',
      ]
      base ||= root_dse(['subschemaSubentry'], sec, usec)[0]['subschemaSubentry'][0]
      base ||= 'cn=schema'
      ent = search2(base, LDAP_SCOPE_BASE, '(objectClass=subschema)',
		    attrs, false, sec, usec)
      return Schema.new(ent[0])
    end

    # Fetch the root DSE (DSA-specific Entry) for the connection. DSA stands
    # for Directory System Agent and simply refers to the LDAP server you are
    # using.
    #
    # +attrs+, if given, is an array of attributes that should be returned
    # from the server. The default list is *subschemaSubentry*,
    # *namingContexts*, *monitorContext*, *altServer*, *supportedControl*,
    # *supportedExtension*, *supportedFeatures*, *supportedSASLMechanisms*
    # and *supportedLDAPVersion*.
    #
    # +sec+ and +usec+ can be used to specify a time-out for the search in
    # seconds and microseconds, respectively.
    #
    def root_dse(attrs = nil, sec = 0, usec = 0)
      attrs ||= [
	'subschemaSubentry',
	'namingContexts',
	'monitorContext',
	'altServer',
	'supportedControl',
	'supportedExtension',
	'supportedFeatures',
	'supportedSASLMechanisms',
	'supportedLDAPVersion',
      ]

      entries = search2('', LDAP_SCOPE_BASE, '(objectClass=*)',
			attrs, false, sec, usec)
      return entries
    end
  end
end
