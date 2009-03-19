# Manipulation of LDIF data.
#
# $Id: ldif.rb,v 1.11 2005/03/03 01:32:07 ianmacd Exp $
#
# Copyright (C) 2005 Ian Macdonald <ian@caliban.org>
#

module LDAP

  # Record objects are embodiments of LDAP operations. They possess a DN,
  # a change type (*LDAP_MOD_ADD*, *LDAP_MOD_DELETE* or *LDAP_MOD_REPLACE*
  # [any of which can be logically AND'ed with *LDAP_MOD_BVALUES*]), a hash of
  # attributes and value arrays, a hash of modification operations (useful
  # only when the change type is *LDAP_MOD_REPLACE*) and an array of
  # LDAP controls.
  #
  # The Record class's primary use is as a transitional medium for LDIF
  # operations parsed by the LDAP::LDIF module. You are unlikely to want to
  # use it in application code.
  #
  class Record
    attr_reader :dn, :change_type, :attrs, :mods, :controls

    def initialize(dn, change_type, attrs, mods=nil, ctls=nil)
      @dn = dn
      @change_type = change_type
      @attrs = attrs
      @mods = mods
      @controls = ctls
    end


    # Send the operation embodied in the Record object to the LDAP::Conn
    # object specified in +conn+.
    #
    def send( conn )
      if @change_type == :MODRDN
	# TODO: How do we deal with 'newsuperior'?
	# The LDAP API's ldap_modrdn2_s() function doesn't seem to use it.
	return conn.modrdn( @dn, @attrs['newrdn'], @attrs['deleteoldrdn'] )
      end

      # Mask out the LDAP_MOD_BVALUES bit, as it's irrelevant here.
      case @change_type & ~LDAP_MOD_BVALUES
      when LDAP_MOD_ADD
	@controls == [] ? conn.add( @dn, @attrs ) :
			  conn.add_ext( @dn, @attrs, @controls, [] )
      when LDAP_MOD_DELETE
	@controls == [] ? conn.delete( @dn ) :
			  conn.delete_ext( @dn, @controls, [] )
      when LDAP_MOD_REPLACE
	@controls == [] ? conn.modify( @dn, @mods ) :
			  conn.modify_ext( @dn, @mods, @controls, [] )
      end

      self
    end


    # Remove common operational attributes from a Record object. This is
    # useful if you have Record objects formed from LDIF data that contained
    # operational attributes. Using LDAP::Record#send to send such an object
    # to an LDAP server is likely to meet with an exception unless the data is
    # first cleaned.
    #
    # In addition, attributes with duplicate values are pruned, as this can
    # also result in an exception.
    #
    def clean

      # TODO: These operational attributes are those commonly used by
      # OpenLDAP 2.2. Others should probably be supported.
      #
      %w[ creatorsname createtimestamp modifiersname modifytimestamp
          entrycsn entryuuid structuralobjectclass ].each do |attr|
	@attrs.delete( attr )
      end

      # Clean out duplicate attribute values.
      @attrs.each_key { |k| @attrs[k].uniq! }

      self
    end

  end


  # This module provides the ability to process LDIF entries and files.
  #
  module LDIF
    LINE_LENGTH = 77

    private

    class Entry < String; end
    class Mod < String; end
    class LDIFError < LDAP::Error; end


    # return *true* if +str+ contains a character with an ASCII value > 127 or
    # a NUL, LF or CR. Otherwise, *false* is returned.
    #
    def LDIF.unsafe_char?( str )
      # This could be written as a single regex, but this is faster.
      str =~ /^[ :]/ || str =~ /[\x00-\x1f\x7f-\xff]/
    end


    # Perform Base64 decoding of +str+. If +concat+ is *true*, LF characters
    # are stripped.
    #
    def LDIF.base64_encode( str, concat=false )
      str = [ str ].pack( 'm' )
      str.gsub!( /\n/, '' ) if concat
      str
    end


    # Perform Base64 encoding of +str+.
    #
    def LDIF.base64_decode( str )
      str.unpack( 'm*' )[0]
    end


    # Read a file from the URL +url+. At this time, the only type of URL
    # supported is the +file://+ URL.
    #
    def LDIF.read_file( url )
      unless url.sub!( %r(^file://), '' )
        raise ArgumentError, "Bad external file reference: #{url}"
      end
  
      # Slurp an external file.
      # TODO: Support other URL types in the future.
      File.open( url ).readlines( nil )[0]
    end


    # This converts an attribute and array of values to LDIF.
    #
    def LDIF.to_ldif( attr, vals )
      ldif = ''

      vals.each do |val|
        sep = ':'
        if unsafe_char?( val )
          sep = '::'
          val = base64_encode( val, true )
        end
      
        firstline_len = LINE_LENGTH - ( "%s%s " % [ attr, sep ] ).length
        ldif << "%s%s %s\n" % [ attr, sep, val.slice!( 0..firstline_len ) ]
      
        while val.length > 0
          ldif << " %s\n" % val.slice!( 0..LINE_LENGTH - 1 )
        end
      end

      ldif

    end


    public


    # Parse the LDIF entry contained in +lines+ and return an LDAP::Record
    # object. +lines+ should be an object that responds to each, such as a
    # string or an array of lines, separated by \n characters.
    #
    def LDIF.parse_entry( lines )
      header = true
      comment = false
      change_type = nil
      sep = nil
      attr = nil
      bvalues = []
      controls = nil
      hash = {}
      mods = {}
      mod_type = nil
      
      lines.each do |line|
	# Skip (continued) comments.
	if line =~ /^#/ || ( comment && line[0..0] == ' ' )
	  comment = true
	  next
	end

	# Skip blank lines.
	next if line =~ /^$/

	# Reset mod type if this entry has more than one mod to make.
	# A '-' continuation is only valid if we've already had a
	# 'changetype: modify' line.
	if line =~ /^-$/ && change_type == LDAP_MOD_REPLACE
	  next
	end

	line.chomp!

	# N.B. Attributes and values can be separated by one or two colons,
	# or one colon and a '<'. Either of these is then followed by zero
	# or one spaces.
	if md = line.match( /^[^ ].*?((:[:<]?) ?)/ )

	  # If previous value was Base64-encoded and is not continued,
	  # we need to decode it now.
	  if sep == '::'
	    if mod_type
	      mods[mod_type][attr][-1] =
		base64_decode( mods[mod_type][attr][-1] )
		bvalues << attr if unsafe_char?( mods[mod_type][attr][-1] )
	    else
	      hash[attr][-1] = base64_decode( hash[attr][-1] )
	      bvalues << attr if unsafe_char?( hash[attr][-1] )
	    end

	  end

	  # Found a attr/value line.
	  attr, val = line.split( md[1], 2 )
	  attr.downcase!

	  # Attribute must be ldap-oid / (ALPHA *(attr-type-chars))
	  if attr !~ /^(?:(?:\d+\.)*\d+|[[:alnum:]-]+)(?:;[[:alnum:]-]+)*$/
	    raise LDIFError, "Invalid attribute: #{attr}"
	  end

	  if attr == 'dn'
	    header = false
	    change_type = nil
	    controls = []
	  end
	  sep = md[2]

	  val = read_file( val ) if sep == ':<'

	  case attr
	  when 'version'
	    # Check the LDIF version.
	    if header
	      if val != '1'
		raise LDIFError, "Unsupported LDIF version: #{val}"
	      else
		header = false
		next
	      end
	    end

	  when 'changetype'
	    change_type = case val
			    when 'add'	     then LDAP_MOD_ADD
			    when 'delete'    then LDAP_MOD_DELETE
			    when 'modify'    then LDAP_MOD_REPLACE
			    when /^modr?dn$/ then :MODRDN
			  end

	    raise LDIFError, "Invalid change type: #{attr}" unless change_type

	  when 'add', 'delete', 'replace'
	    unless change_type == LDAP_MOD_REPLACE
	      raise LDIFError, "Cannot #{attr} here."
	    end

	    mod_type = case attr
		         when 'add'	then LDAP_MOD_ADD
		         when 'delete'	then LDAP_MOD_DELETE
		         when 'replace'	then LDAP_MOD_REPLACE
		       end

	    mods[mod_type] ||= {}
	    mods[mod_type][val] ||= []

	  when 'control'

	    oid, criticality = val.split( / /, 2 )

	    unless oid =~ /(?:\d+\.)*\d+/
	      raise LDIFError, "Bad control OID: #{oid}" 
	    end

	    if criticality
	      md = criticality.match( /(:[:<]?) ?/ )
	      ctl_sep = md[1] if md
	      criticality, value = criticality.split( /:[:<]? ?/, 2 )

	      if criticality !~ /^(?:true|false)$/
	        raise LDIFError, "Bad control criticality: #{criticality}"
	      end

	      # Convert 'true' or 'false'. to_boolean would be nice. :-)
	      criticality = eval( criticality )
	    end

	    if value
	      value = base64_decode( value ) if ctl_sep == '::'
	      value = read_file( value ) if ctl_sep == ':<'
	      value = Control.encode( value )
	    end

	    controls << Control.new( oid, value, criticality )
	  else

	    # Convert modrdn's deleteoldrdn from '1' to true, anything else
	    # to false. Should probably raise an exception if not '0' or '1'.
	    #
	    if change_type == :MODRDN && attr == 'deleteoldrdn'
	      val = val == '1' ? true : false
	    end

	    if change_type == LDAP_MOD_REPLACE
	      mods[mod_type][attr] << val
	    else
	      hash[attr] ||= []
	      hash[attr] << val
	    end

	    comment = false

	    # Make a note of this attribute if value is binary.
	    bvalues << attr if unsafe_char?( val )
	  end

	else

	  # Check last line's separator: if not a binary value, the
	  # continuation line must be indented. If a comment makes it this
	  # far, that's also an error.
	  #
	  if sep == ':' && line[0..0] != ' ' || comment
	    raise LDIFError, "Improperly continued line: #{line}"
	  end

	  # OK; this is a valid continuation line.

	  # Append line except for initial space.
	  line[0] = '' if line[0..0] == ' '

	  if change_type == LDAP_MOD_REPLACE
	    # Append to last value of current mod type.
	    mods[mod_type][attr][-1] << line
	  else
	    # Append to last value.
	    hash[attr][-1] << line
	  end
	end
	
      end

      # If last value in LDIF entry was Base64-encoded, we need to decode
      # it now.
      if sep == '::'
        if mod_type
          mods[mod_type][attr][-1] =
	    base64_decode( mods[mod_type][attr][-1] )
	  bvalues << attr if unsafe_char?( mods[mod_type][attr][-1] )
        else
          hash[attr][-1] = base64_decode( hash[attr][-1] )
	  bvalues << attr if unsafe_char?( hash[attr][-1] )
        end
      end

      # Remove and remember DN.
      dn = hash.delete( 'dn' )[0]

      # This doesn't really matter, but let's be anal about it, because it's
      # not an attribute and doesn't belong here.
      bvalues.delete( 'dn' )

      # If there's no change type, it's just plain LDIF data, so we'll treat
      # it like an addition.
      change_type ||= LDAP_MOD_ADD

      case change_type
      when LDAP_MOD_ADD

	mods[LDAP_MOD_ADD] = []

	hash.each do |attr_local, val|
	  if bvalues.include?( attr_local )
	    ct = LDAP_MOD_ADD | LDAP_MOD_BVALUES
	  else
	    ct = LDAP_MOD_ADD
	  end

	  mods[LDAP_MOD_ADD] << LDAP.mod( ct, attr_local, val )
	end

      when LDAP_MOD_DELETE

	# Nothing to do.

      when LDAP_MOD_REPLACE

	raise LDIFError, "mods should not be empty" if mods == {}

	new_mods = {}

	mods.each do |mod_type_local,attrs|
	  attrs.each_key do |attr_local|
	    if bvalues.include?( attr_local )
	      mt = mod_type_local | LDAP_MOD_BVALUES
	    else
	      mt = mod_type_local
	    end

	    new_mods[mt] ||= {}
	    new_mods[mt][attr_local] = mods[mod_type_local][attr_local]
	  end
	end

	mods = new_mods

      when :MODRDN

	# Nothing to do.

      end

      Record.new( dn, change_type, hash, mods, controls )
    end


    # Open and parse a file containing LDIF entries. +file+ should be a string
    # containing the path to the file. If +sort+ is true, the resulting array
    # of LDAP::Record objects will be sorted on DN length, which can be useful
    # to avoid a later attempt to process an entry whose parent does not yet
    # exist. This can easily happen if your LDIF file is unordered, which is
    # likely if it was produced with a tool such as <em>slapcat(8)</em>.
    #
    # If a block is given, each LDAP::Record object will be yielded to the
    # block and *nil* will be returned instead of the array. This is much less
    # memory-intensive when parsing a large LDIF file.
    #
    def LDIF.parse_file( file, sort=false ) # :yield: record

      File.open( file ) do |f|
	entries = []
	entry = false
	header = true
	version = false

	while line = f.gets

	  if line =~ /^dn:/
	    header = false

	    if entry && ! version
	      if block_given?
		yield parse_entry( entry )
	      else
	        entries << parse_entry( entry )
	      end
	    end

	    if version
	      entry << line
	      version = false
	    else
	      entry = [ line ]
	    end

	    next
	  end

	  if header && line.downcase =~ /^version/
	    entry = [ line ]
	    version = true
	    next
	  end
	
	  entry << line
	end

	if block_given?
	  yield parse_entry( entry )
	  nil
	else
	  entries << parse_entry( entry )

	  # Sort entries if sorting has been requested.
	  entries.sort! { |x,y| x.dn.length <=> y.dn.length } if sort
	  entries
	end

      end

    end


    # Given the DN, +dn+, convert a single LDAP::Mod or an array of
    # LDAP::Mod objects, given in +mods+, to LDIF.
    #
    def LDIF.mods_to_ldif( dn, *mods )
      ldif = "dn: %s\nchangetype: modify\n" % dn
      plural = false

      mods.flatten.each do |mod|
        # TODO: Need to dynamically assemble this case statement to add
        # OpenLDAP's increment change type, etc.
        change_type = case mod.mod_op & ~LDAP_MOD_BVALUES
			when LDAP_MOD_ADD     then 'add'
			when LDAP_MOD_DELETE  then 'delete'
			when LDAP_MOD_REPLACE then 'replace'
		      end

        ldif << "-\n" if plural
        ldif << LDIF.to_ldif( change_type, mod.mod_type )
        ldif << LDIF.to_ldif( mod.mod_type, mod.mod_vals )

        plural = true
      end

      LDIF::Mod.new( ldif )
    end

  end


  class Entry

    # Convert an LDAP::Entry to LDIF.
    #
    def to_ldif
      ldif = "dn: %s\n" % get_dn

      get_attributes.each do |attr|
	get_values( attr ).each do |val|
	  ldif << LDIF.to_ldif( attr, [ val ] )
	end
      end

      LDIF::Entry.new( ldif )
    end

    alias_method :to_s, :to_ldif
  end

  
  class Mod

    # Convert an LDAP::Mod with the DN given in +dn+ to LDIF.
    #
    def to_ldif( dn )
      ldif = "dn: %s\n" % dn

      # TODO: Need to dynamically assemble this case statement to add
      # OpenLDAP's increment change type, etc.
      case mod_op & ~LDAP_MOD_BVALUES
      when LDAP_MOD_ADD
	ldif << "changetype: add\n"
      when LDAP_MOD_DELETE
	ldif << "changetype: delete\n"
      when LDAP_MOD_REPLACE
	return LDIF.mods_to_ldif( dn, self )
      end

      ldif << LDIF.to_ldif( mod_type, mod_vals )
      LDIF::Mod.new( ldif )
    end

    alias_method :to_s, :to_ldif
  end

end
