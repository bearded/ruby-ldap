# $Id: tc_search.rb,v 1.4 2006/02/12 19:55:59 ianmacd Exp $
#
# A suite of unit tests for testing Ruby/LDAP search functionality.

require 'ldap'
require 'ldap/control'
require 'test/unit'
require './setup'

class TC_SearchTest < TC_LDAPTest

  # Ensure that giving an incorrect attribute argument raises an exception
  # and that passing a string instead of an array is treated as a single
  # element array.
  #
  def test_attrs
    assert_raise( TypeError ) do
      @@conn.search( @@naming_context, LDAP::LDAP_SCOPE_ONELEVEL,
		     '(objectClass=*)', false )
    end

    @@conn.search( @@naming_context, LDAP::LDAP_SCOPE_ONELEVEL,
		   '(objectClass=*)', [], true ) do |x|
      assert_nil( x['objectClass'] )
      break
    end

    @@conn.search( @@naming_context, LDAP::LDAP_SCOPE_ONELEVEL,
		   '(objectClass=*)', 'objectClass' ) do |x|
      x = x.to_hash
      x.delete( 'dn' )
      assert( x.to_hash.keys == [ 'objectClass' ] )
      break
    end
  end

  # Ensure that we can sort on a given attribute.
  #
  def test_sort_attr
    ou = []
    @@conn.search( @@naming_context, LDAP::LDAP_SCOPE_ONELEVEL,
		   '(ou=*)' ) do |x|
      ou << x['ou']
    end
    ou.flatten!

    sorted_ou = []
    @@conn.search( @@naming_context, LDAP::LDAP_SCOPE_ONELEVEL,
		   '(ou=*)', nil, nil, 0, 0, 'ou' ) do |x|
      sorted_ou << x['ou']
    end
    sorted_ou.flatten!

    assert_not_equal( ou, sorted_ou )
    assert_equal( ou.sort, sorted_ou )
  end

  # Ensure that we can pass a proc object to use for sorting.
  #
  def test_sort_proc
    ct = []
    @@conn.search( @@naming_context, LDAP::LDAP_SCOPE_ONELEVEL,
		   '(objectClass=*)', [ 'createTimestamp' ] ) do |x|
      ct << x['createTimestamp']
    end
    ct.flatten!

    sorted_ct = []
    s_proc = proc { |a,b| b <=> a }
    @@conn.search( @@naming_context, LDAP::LDAP_SCOPE_ONELEVEL,
		   '(objectClass=*)', [ 'createTimestamp' ], nil, 0, 0,
		   'createTimestamp', s_proc ) do |x|
      sorted_ct << x['createTimestamp']
    end
    sorted_ct.flatten!

    assert_not_equal( ct, sorted_ct )
    assert_equal( ct.sort( &s_proc ), sorted_ct )
  end

  # Ensure that the paged results control works properly.
  #
  def test_paged_results
    total = 0
    page_size = 1
    cookie = ''

    loop do
      ber_string = LDAP::Control.encode( page_size, cookie )
      ctrl = LDAP::Control.new( LDAP::LDAP_CONTROL_PAGEDRESULTS,
			        ber_string,
				true )
      @@conn.set_option( LDAP::LDAP_OPT_SERVER_CONTROLS, [ ctrl ] )

      this_page = nil
      assert_nothing_raised do
	begin
          this_page = @@conn.search2( @@naming_context,
				      LDAP::LDAP_SCOPE_ONELEVEL,
				      '(objectclass=*)' )
	rescue LDAP::ResultError
	  @@conn = nil
	  raise
	end
      end
      total += this_page.size
      assert_equal( page_size, this_page.size )

      @@conn.controls.each do |c|
        if c.oid == LDAP::LDAP_CONTROL_PAGEDRESULTS
          ctrl = c
          break
        end
      end

      assert_equal( ctrl.oid, LDAP::LDAP_CONTROL_PAGEDRESULTS )

      fetched_size, cookie = ctrl.decode
      page_size = fetched_size if fetched_size.to_i > 0

      break if cookie.empty?
    end

    # Reset connection.
    @@conn = nil
    setup

    unpaged = @@conn.search2( @@naming_context, LDAP::LDAP_SCOPE_ONELEVEL,
			      '(objectclass=*)' )

    # Does the total number of results match the equivalent unpaged search?
    # This has a race condition, but we assume the number of top-level OUs is
    # more or less static. :-)
    assert_equal( total, unpaged.size )
  end

end
