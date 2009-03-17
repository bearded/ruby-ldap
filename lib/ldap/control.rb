# Manipulation of LDAP control data.
#
# $Id: control.rb,v 1.2 2005/02/28 05:02:25 ianmacd Exp $
#
# Copyright (C) 2004 Ian Macdonald <ian@caliban.org>
#

module LDAP
  class Control

    require 'openssl'

    # Take +vals+, produce an Array of values in ASN.1 format and then
    # convert the Array to DER.
    #
    def Control.encode( *vals )
      encoded_vals = []
     
      vals.each do |val|
        encoded_vals <<
          case val
          when Integer
            OpenSSL::ASN1::Integer( val )
          when String
            OpenSSL::ASN1::OctetString.new( val )
          else
            # What other types may exist?
          end
      end
   
      OpenSSL::ASN1::Sequence.new( encoded_vals ).to_der
    end


    # Take an Array of ASN.1 data and return an Array of decoded values.
    #
    def decode
      values = []

      OpenSSL::ASN1::decode( self.value ).value.each do |val|
	values << val.value
      end

      values
    end

  end
end
