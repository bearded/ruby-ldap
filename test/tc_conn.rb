# $Id: tc_conn.rb,v 1.3 2005/03/15 01:43:59 ianmacd Exp $
#
# A suite of unit tests for testing Ruby/LDAP connection functionality.

require 'ldap'
require 'test/unit'
require './setup'

class TC_ConnectionTest < TC_LDAPTest

  # Ensure that rebinding works.
  #
  def test_rebind
    id = @@conn.object_id

    assert_nothing_raised do
      @@conn.unbind
      @@conn.bind
    end

    id2 = @@conn.object_id
    assert_equal( id, id2 )

    assert_nothing_raised do
      @@conn.unbind
      @@conn.simple_bind
    end

    id2 = @@conn.object_id
    assert_equal( id, id2 )
  end

  def test_double_bind
    assert_raises( LDAP::Error ) { @@conn.bind }
    assert_raises( LDAP::Error ) { @@conn.simple_bind }
  end

  def test_double_unbind
    assert_nothing_raised { @@conn.unbind }
    assert_raises( LDAP::InvalidDataError ) { @@conn.unbind }
  end

  def test_bound?
    assert( @@conn.bound? )
    @@conn.unbind
    assert( ! @@conn.bound? )
  end

  def test_sasl_bind
    @@conn = LDAP::Conn.new( @@host )
    @@conn.sasl_quiet = true
    
    assert_nothing_raised { @@conn.sasl_bind( '', '' ) }
    
    @@conn = nil
  end

  def test_double_sasl_bind
    @@conn = LDAP::Conn.new( @@host )
    @@conn.sasl_quiet = true

    assert_nothing_raised { @@conn.sasl_bind( '', '' ) }
    assert_raises( LDAP::Error ) { @@conn.sasl_bind( '', '' ) }

    @@conn = nil
  end

  def test_sasl_rebind
    @@conn = LDAP::Conn.new( @@host )
    @@conn.sasl_quiet = true

    id = @@conn.object_id

    assert_nothing_raised do
      @@conn.unbind
      @@conn.sasl_bind( '', '' )
    end

    id2 = @@conn.object_id
    assert_equal( id, id2 )

    @@conn = nil
  end

  def test_ssl_rebind
    @@conn = LDAP::SSLConn.new( @@host, LDAP::LDAPS_PORT )

    id = @@conn.object_id

    assert_nothing_raised do
      @@conn.bind
      @@conn.unbind
      @@conn.bind
    end

    id2 = @@conn.object_id
    assert_equal( id, id2 )

    @@conn = nil
  end

  def test_ssl_open
    assert_raises( NotImplementedError ) { LDAP::SSLConn.open( @@host ) }
  end

  def test_ssl_starttls_rebind
    @@conn = LDAP::SSLConn.new( @@host, LDAP::LDAP_PORT, true )

    id = @@conn.object_id

    assert_nothing_raised do
      @@conn.bind
      @@conn.unbind
      @@conn.bind
    end

    id2 = @@conn.object_id
    assert_equal( id, id2 )

    @@conn = nil
  end


end
