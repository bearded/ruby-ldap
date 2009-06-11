# $Id: tc_schema.rb,v 1.4 2005/03/13 10:11:41 ianmacd Exp $
#
# A suite of unit tests for testing Ruby/LDAP schema functionality.

require 'ldap'
require 'ldap/schema'
require 'test/unit'
require './setup'

class TC_SchemaTest < TC_LDAPTest

  def test_schema
    schema = @@conn.schema
    assert_instance_of( LDAP::Schema, schema )
    assert( schema.key?( 'attributeTypes' ) )
    assert( schema.key?( 'ldapSyntaxes' ) )
    assert( schema.key?( 'matchingRules' ) )
    assert( schema.key?( 'matchingRuleUse' ) )
    assert( schema.key?( 'objectClasses' ) )
  end

  def test_root_dse
    root_dse = @@conn.root_dse[0]
    assert( root_dse.key?( 'subschemaSubentry' ) )
    assert( root_dse.key?( 'namingContexts' ) )
    assert( root_dse.key?( 'supportedSASLMechanisms' ) )
    assert( root_dse.key?( 'supportedControl' ) )
    assert( root_dse.key?( 'supportedExtension' ) )
    assert( root_dse.key?( 'supportedLDAPVersion' ) )
  end
    
end
