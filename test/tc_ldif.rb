# $Id: tc_ldif.rb,v 1.5 2005/02/26 01:42:27 ianmacd Exp $
#
# A suite of unit tests for testing Ruby/LDAP LDIF functionality. 

require 'ldap'
require 'ldap/ldif'
require 'ldap/control'
require 'test/unit'

class TC_LDIFTest < Test::Unit::TestCase

  include LDAP::LDIF

  def test_version_entry
    ldif = File.open( 'data/ldif1.txt' ) { |f| f.readlines }
    entry = nil
    assert_nothing_raised { entry = LDAP::LDIF.parse_entry( ldif ) }
    assert_instance_of( LDAP::Record, entry )
    assert_instance_of( String, entry.dn )
    assert_instance_of( Array, entry.attrs['objectclass'] )
    assert( entry.attrs['objectclass'].length > 1 )
  end

  def test_bad_version_entry
    ldif = File.open( 'data/ldif2.txt' ) { |f| f.readlines }
    assert_raise( LDIFError ) { LDAP::LDIF.parse_entry( ldif ) }
  end

  def test_no_version_entry
    ldif = File.open( 'data/ldif3.txt' ) { |f| f.readlines }
    assert_nothing_raised { LDAP::LDIF.parse_entry( ldif ) }
  end

  def test_file
    entries = LDAP::LDIF.parse_file( 'data/ldif4.txt' )
    assert_instance_of( Array, entries )
    assert_instance_of( Hash, entries[0].attrs )
    assert_not_equal( {}, entries[0].attrs )
  end

  def test_folded_attribute_entry
    ldif = File.open( 'data/ldif5.txt' ) { |f| f.readlines }
    entry = nil
    assert_nothing_raised { entry = LDAP::LDIF.parse_entry( ldif ) }
    assert_no_match( /\n/, entry.attrs['description'][0] )
    assert( entry.attrs['description'][0].length > LDAP::LDIF::LINE_LENGTH )
  end

  def test_base64_value_entry
    ldif = File.open( 'data/ldif6.txt' ) { |f| f.readlines }
    entry = LDAP::LDIF.parse_entry( ldif )
    assert_match( /\r/, entry.attrs['description'][0] )
  end

  def test_utf8_file
    entries = LDAP::LDIF.parse_file( 'data/ldif7.txt' )
    assert_instance_of( Array, entries )
    assert_instance_of( Hash, entries[0].attrs )
    assert_not_equal( {}, entries[0].attrs )
  end

  def test_external_file_entry
    ldif = File.open( 'data/ldif8.txt' ) { |f| f.readlines }
    entry = LDAP::LDIF.parse_entry( ldif )
    assert( entry.attrs['jpegphoto'][0].size > 1024 )
  end

  def test_change_records_file
    entries = LDAP::LDIF.parse_file( 'data/ldif9.txt' )
    assert_instance_of( Array, entries )
    assert_instance_of( Hash, entries[0].attrs )
    assert_not_equal( {}, entries[0].attrs )
  end

  def test_bad_line_entry
    ldif = File.open( 'data/ldif10.txt' ) { |f| f.readlines }
    assert_raise( LDIFError ) { LDAP::LDIF.parse_entry( ldif ) }
  end

  def test_bad_attr_entry
    ldif = File.open( 'data/ldif11.txt' ) { |f| f.readlines }
    assert_raise( LDIFError ) { LDAP::LDIF.parse_entry( ldif ) }
  end

  def test_change_record_binary_replace_entry
    ldif = File.open( 'data/ldif12.txt' ) { |f| f.readlines }
    entry = LDAP::LDIF.parse_entry( ldif )
    assert( entry.mods.keys.include?( LDAP::LDAP_MOD_REPLACE |
				      LDAP::LDAP_MOD_BVALUES ) )
  end

  def test_change_record_control
    ldif = File.open( 'data/ldif13.txt' ) { |f| f.readlines }
    entry = LDAP::LDIF.parse_entry( ldif )
    assert_instance_of( LDAP::Control, entry.controls[0] )
    assert_equal( entry.controls[0].oid, '1.2.840.113556.1.4.805' )
    assert( entry.controls[0].iscritical )
    assert_nil( entry.controls[0].value )
  end

  def test_change_record_control2
    ldif = File.open( 'data/ldif14.txt' ) { |f| f.readlines }
    entry = LDAP::LDIF.parse_entry( ldif )
    assert_instance_of( LDAP::Control, entry.controls[0] )
    assert_equal( entry.controls[0].oid, '1.2.3.4' )
    assert_equal( entry.controls[0].iscritical, false )
    assert_not_nil( entry.controls[0].value )
  end

  def test_mod_to_ldif
    mod = LDAP.mod( LDAP::LDAP_MOD_ADD | LDAP::LDAP_MOD_BVALUES,
		    'mailRoutingAddress', ['a', 'b'] )
    assert_instance_of( LDAP::LDIF::Mod,
		        mod.to_ldif( 'uid=foo,dc=example,dc=com' ) )
    assert_equal( <<LDIF, mod.to_ldif( 'uid=foo,dc=example,dc=com' ) )
dn: uid=foo,dc=example,dc=com
changetype: add
mailRoutingAddress: a
mailRoutingAddress: b
LDIF

    mod = LDAP.mod( LDAP::LDAP_MOD_REPLACE | LDAP::LDAP_MOD_BVALUES,
		    'mailRoutingAddress', ['a', 'b'] )
    assert_equal( <<LDIF, mod.to_ldif( 'uid=foo,dc=example,dc=com' ) )
dn: uid=foo,dc=example,dc=com
changetype: modify
replace: mailRoutingAddress
mailRoutingAddress: a
mailRoutingAddress: b
LDIF

    mod = LDAP.mod( LDAP::LDAP_MOD_DELETE, 'mailRoutingAddress', ['a', 'b'] )
    assert_equal( <<LDIF, mod.to_ldif( 'uid=foo,dc=example,dc=com' ) )
dn: uid=foo,dc=example,dc=com
changetype: delete
mailRoutingAddress: a
mailRoutingAddress: b
LDIF
  end

  def test_mods_to_ldif

    # Try passing an array of mods to LDAP::LDIF.mods_to_ldif.

    # This must be a single line for the heredoc to work.
    assert_equal( <<LDIF, LDAP::LDIF.mods_to_ldif( 'uid=ianmacd,dc=foo', [ LDAP.mod( LDAP::LDAP_MOD_ADD | LDAP::LDAP_MOD_BVALUES, 'mailRoutingAddress', ['a', 'b'] ), LDAP.mod( LDAP::LDAP_MOD_DELETE, 'location', [ 'amsterdam'] ), LDAP.mod( LDAP::LDAP_MOD_REPLACE, 'telephonenumber', [ '+1 408 555 1234', '+1 408 555 5678' ] ), LDAP.mod( LDAP::LDAP_MOD_DELETE, 'office', [] ) ] ) )
dn: uid=ianmacd,dc=foo
changetype: modify
add: mailRoutingAddress
mailRoutingAddress: a
mailRoutingAddress: b
-
delete: location
location: amsterdam
-
replace: telephonenumber
telephonenumber: +1 408 555 1234
telephonenumber: +1 408 555 5678
-
delete: office
LDIF

  # Try passing a single mod to LDAP::LDIF.mods_to_ldif.
  assert_equal( <<LDIF, LDAP::LDIF.mods_to_ldif( 'uid=ianmacd,dc=google,dc=com', LDAP.mod( LDAP::LDAP_MOD_REPLACE, 'telephonenumber', [ '+1 408 555 1234', '+1 408 555 5678' ] ) ) )
dn: uid=ianmacd,dc=google,dc=com
changetype: modify
replace: telephonenumber
telephonenumber: +1 408 555 1234
telephonenumber: +1 408 555 5678
LDIF

  end

end
