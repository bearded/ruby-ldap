/* -*- C -*-
 *
 * ldap.c
 * $Id: ldap.c,v 1.14 2005/03/15 10:07:48 ianmacd Exp $
 */

#include "ruby.h"
#include "rbldap.h"

VALUE rb_mLDAP;
VALUE rb_eLDAP_Error;
VALUE rb_eLDAP_ResultError;
VALUE rb_eLDAP_InvalidDataError;
VALUE rb_eLDAP_InvalidEntryError;

VALUE
rb_ldap_class_new (int argc, VALUE argv[], VALUE klass)
{
  VALUE obj;

  obj = rb_funcall (klass, rb_intern ("allocate"), 0);
  rb_obj_call_init (obj, argc, argv);

  return obj;
}

VALUE
rb_ldap_dummy_method (int argc, VALUE argv[], VALUE self)
{
  /* do nothing */
  return Qnil;
}

/*
 * call-seq:
 * LDAP.err2string(err)  => String
 *
 * Return the text string associated with the LDAP error, +err+.
 */
VALUE
rb_ldap_err2string (VALUE self, VALUE err)
{
  char *cmsg;
  VALUE msg;

  cmsg = ldap_err2string (NUM2INT (err));
  msg = rb_tainted_str_new2 (cmsg);

  return msg;
}

/*
 * call-seq:
 * LDAP.dn2ufn(dn)  => String or nil
 *
 * Translate the DN, +dn+, to a more User-Friendly Name (UFN).
 *
 * For example:
 *
 * <code>LDAP.dn2ufn('uid=ianmacd,ou=People,dc=google,dc=com')</code>
 *
 * produces:
 *
 * ianmacd, People, google.com
 *
 * The UFN format is described in
 * RFC1781[http://www.faqs.org/rfcs/rfc1781.html].
 */
VALUE
rb_ldap_dn2ufn (VALUE self, VALUE dn)
{
  char *c_dn;
  char *c_ufn;

  if (dn == Qnil)
    {
      return Qnil;
    }

  c_dn = StringValueCStr (dn);
  if ((c_ufn = ldap_dn2ufn (c_dn)))
    {
      return rb_tainted_str_new2 (c_ufn);
    }
  else
    {
      return Qnil;
    }
}

/*
 * call-seq:
 * LDAP.mod(mod_type, attr, vals)  => LDAP::Mod
 *
 * Create a new LDAP::Mod object of type, +mod_type+. This is most commonly
 * *LDAP_MOD_ADD*, *LDAP_MOD_REPLACE* or *LDAP_MOD_DELETE*, although some LDAP
 * servers may offer extension types. 
 *
 * +attr+ should be the name of the attribute on which to operate, whilst
 * +vals+ is an array of values pertaining to +attr+. If +vals+ contains
 * binary data, +mod_type+ should be logically OR'ed (|) with
 * *LDAP_MOD_BVALUES*.
 *
 * LDAP::Mod objects can be passed to methods in the LDAP::Conn class, such as
 * Conn#add, Conn#add_ext, Conn#modify and Conn#modify_ext.
 */
static VALUE
rb_ldap_mod_s_new (int argc, VALUE argv[], VALUE klass)
{
  return rb_ldap_class_new (argc, argv, rb_cLDAP_Mod);
}

static VALUE
rb_ldap_hash2mods_i (VALUE type_vals, VALUE tmp)
{
  VALUE type, vals, op, result;
  VALUE args[3];

  op = rb_ary_entry (tmp, 0);
  result = rb_ary_entry (tmp, 1);

  type = rb_ary_entry (type_vals, 0);
  vals = rb_ary_entry (type_vals, 1);

  args[0] = op, args[1] = type, args[2] = vals;
  rb_ary_push (result, rb_ldap_mod_s_new (3, args, rb_cLDAP_Mod));
  return Qnil;
}

/*
 * call-seq:
 * LDAP.hash2mods(mod_type, hash)  => Array of LDAP::Mod
 *
 * Convert a hash into an array of LDAP::Mod objects. +mod_type+ should
 * contain the mod type, which is most commonly *LDAP_MOD_ADD*,
 * *LDAP_MOD_REPLACE* or *LDAP_MOD_DELETE*, although some LDAP servers may
 * offer extension types.
 */
VALUE
rb_ldap_hash2mods (VALUE self, VALUE op, VALUE hash)
{
  VALUE tmp;

  tmp = rb_assoc_new (op, rb_ary_new ());
  rb_iterate (rb_each, hash, rb_ldap_hash2mods_i, tmp);

  return rb_ary_entry (tmp, 1);
}

/*
 * call-seq:
 * LDAP.entry2hash(entry)  => Hash
 *
 * Convert the entry, +entry+, to a hash.
 */
VALUE
rb_ldap_entry2hash (VALUE self, VALUE entry)
{
  return rb_ldap_entry_to_hash (entry);
}



extern void Init_ldap_entry ();
extern void Init_ldap_conn ();
extern void Init_ldap_sslconn ();
extern void Init_ldap_saslconn ();
extern void Init_ldap_mod ();
extern void Init_ldap_misc ();

/* Document-class: LDAP
 *
 * Container module for LDAP-related classes.
 */
void
Init_ldap ()
{
  rb_mLDAP = rb_define_module ("LDAP");

  rb_define_const (rb_mLDAP, "LDAP_VERSION", INT2NUM (LDAP_VERSION));

#ifdef LDAP_VERSION1
  rb_define_const (rb_mLDAP, "LDAP_VERSION1", INT2NUM (LDAP_VERSION1));
#endif

#ifdef LDAP_VERSION2
  rb_define_const (rb_mLDAP, "LDAP_VERSION2", INT2NUM (LDAP_VERSION2));
#endif

#ifdef LDAP_VERSION3
  rb_define_const (rb_mLDAP, "LDAP_VERSION3", INT2NUM (LDAP_VERSION3));
#endif

#ifdef LDAP_VERSION_MAX
  rb_define_const (rb_mLDAP, "LDAP_VERSION_MAX", INT2NUM (LDAP_VERSION_MAX));
#else
  rb_define_const (rb_mLDAP, "LDAP_VERSION_MAX", INT2NUM (LDAP_VERSION));
#endif

  rb_define_const (rb_mLDAP, "VERSION",
		   rb_tainted_str_new2 (RB_LDAP_VERSION));
  rb_define_const (rb_mLDAP, "MAJOR_VERSION",
		   INT2NUM (RB_LDAP_MAJOR_VERSION));
  rb_define_const (rb_mLDAP, "MINOR_VERSION",
		   INT2NUM (RB_LDAP_MINOR_VERSION));
  rb_define_const (rb_mLDAP, "PATCH_VERSION",
		   INT2NUM (RB_LDAP_PATCH_VERSION));

#ifdef LDAP_API_INFO_VERSION
  rb_define_const (rb_mLDAP, "LDAP_API_INFO_VERSION",
		   INT2NUM (LDAP_API_INFO_VERSION));
#else
  rb_define_const (rb_mLDAP, "LDAP_API_INFO_VERSION", Qnil);
#endif

#ifdef LDAP_VENDOR_VERSION
  rb_define_const (rb_mLDAP, "LDAP_VENDOR_VERSION",
		   INT2NUM (LDAP_VENDOR_VERSION));
#else
  rb_define_const (rb_mLDAP, "LDAP_VENDOR_VERSION", Qnil);
#endif
#ifdef LDAP_VENDOR_NAME
  rb_define_const (rb_mLDAP, "LDAP_VENDOR_NAME",
		   rb_tainted_str_new2 (LDAP_VENDOR_NAME));
#else
  rb_define_const (rb_mLDAP, "LDAP_VENDOR_NAME", Qnil);
#endif

#ifdef LDAP_API_VERSION
  rb_define_const (rb_mLDAP, "LDAP_API_VERSION", INT2NUM (LDAP_API_VERSION));
#else
  rb_define_const (rb_mLDAP, "LDAP_API_VERSION", Qnil);
#endif

  rb_define_const (rb_mLDAP, "LDAP_PORT", INT2NUM (389));
  rb_define_const (rb_mLDAP, "LDAPS_PORT", INT2NUM (636));
  rb_eLDAP_Error =
    rb_define_class_under (rb_mLDAP, "Error", rb_eStandardError);
  rb_eLDAP_ResultError =
    rb_define_class_under (rb_mLDAP, "ResultError", rb_eLDAP_Error);
  rb_eLDAP_InvalidDataError =
    rb_define_class_under (rb_mLDAP, "InvalidDataError", rb_eLDAP_Error);
  rb_eLDAP_InvalidEntryError =
    rb_define_class_under (rb_mLDAP, "InvalidEntryError",
			   rb_eLDAP_InvalidDataError);


  rb_define_module_function (rb_mLDAP, "err2string", rb_ldap_err2string, 1);
  rb_define_module_function (rb_mLDAP, "dn2ufn", rb_ldap_dn2ufn, 1);
  rb_define_module_function (rb_mLDAP, "mod", rb_ldap_mod_s_new, -1);
  rb_define_module_function (rb_mLDAP, "hash2mods", rb_ldap_hash2mods, 2);
  rb_define_module_function (rb_mLDAP, "entry2hash", rb_ldap_entry2hash, 1);

  /* the following error code must be defined in ldap.h */
#define rb_ldap_define_err_code(code) rb_define_const(rb_mLDAP,#code,INT2NUM(code))
  rb_ldap_define_err_code (LDAP_SUCCESS);
  rb_ldap_define_err_code (LDAP_OPERATIONS_ERROR);
  rb_ldap_define_err_code (LDAP_PROTOCOL_ERROR);
  rb_ldap_define_err_code (LDAP_TIMELIMIT_EXCEEDED);
  rb_ldap_define_err_code (LDAP_SIZELIMIT_EXCEEDED);
  rb_ldap_define_err_code (LDAP_COMPARE_FALSE);
  rb_ldap_define_err_code (LDAP_COMPARE_TRUE);
#ifdef LDAP_STRONG_AUTH_NOT_SUPPORTED
  rb_ldap_define_err_code (LDAP_STRONG_AUTH_NOT_SUPPORTED);
#endif
#ifdef LDAP_AUTH_METHOD_NOT_SUPPORTED
  rb_ldap_define_err_code (LDAP_AUTH_METHOD_NOT_SUPPORTED);
#endif
  rb_ldap_define_err_code (LDAP_STRONG_AUTH_REQUIRED);
#ifdef LDAP_REFERRAL
  rb_ldap_define_err_code (LDAP_REFERRAL);
#endif
#ifdef LDAP_ADMINLIMIT_EXCEEDED
  rb_ldap_define_err_code (LDAP_ADMINLIMIT_EXCEEDED);
#endif
#ifdef LDAP_UNAVAILABLE_CRITICAL_EXTENSION
  rb_ldap_define_err_code (LDAP_UNAVAILABLE_CRITICAL_EXTENSION);
#endif
#ifdef LDAP_CONFIDENTIALITY_REQUIRED
  rb_ldap_define_err_code (LDAP_CONFIDENTIALITY_REQUIRED);
#endif
#ifdef LDAP_SASL_BIND_IN_PROGRESS
  rb_ldap_define_err_code (LDAP_SASL_BIND_IN_PROGRESS);
#endif
#ifdef LDAP_PARTIAL_RESULTS
  rb_ldap_define_err_code (LDAP_PARTIAL_RESULTS);
#endif
  rb_ldap_define_err_code (LDAP_NO_SUCH_ATTRIBUTE);
  rb_ldap_define_err_code (LDAP_UNDEFINED_TYPE);
  rb_ldap_define_err_code (LDAP_INAPPROPRIATE_MATCHING);
  rb_ldap_define_err_code (LDAP_CONSTRAINT_VIOLATION);
  rb_ldap_define_err_code (LDAP_TYPE_OR_VALUE_EXISTS);
  rb_ldap_define_err_code (LDAP_INVALID_SYNTAX);
  rb_ldap_define_err_code (LDAP_NO_SUCH_OBJECT);
  rb_ldap_define_err_code (LDAP_ALIAS_PROBLEM);
  rb_ldap_define_err_code (LDAP_INVALID_DN_SYNTAX);
  rb_ldap_define_err_code (LDAP_IS_LEAF);
  rb_ldap_define_err_code (LDAP_ALIAS_DEREF_PROBLEM);
  rb_ldap_define_err_code (LDAP_INAPPROPRIATE_AUTH);
  rb_ldap_define_err_code (LDAP_INVALID_CREDENTIALS);
  rb_ldap_define_err_code (LDAP_INSUFFICIENT_ACCESS);
  rb_ldap_define_err_code (LDAP_BUSY);
  rb_ldap_define_err_code (LDAP_UNAVAILABLE);
  rb_ldap_define_err_code (LDAP_UNWILLING_TO_PERFORM);
  rb_ldap_define_err_code (LDAP_LOOP_DETECT);
  rb_ldap_define_err_code (LDAP_NAMING_VIOLATION);
  rb_ldap_define_err_code (LDAP_OBJECT_CLASS_VIOLATION);
  rb_ldap_define_err_code (LDAP_NOT_ALLOWED_ON_NONLEAF);
  rb_ldap_define_err_code (LDAP_NOT_ALLOWED_ON_RDN);
  rb_ldap_define_err_code (LDAP_ALREADY_EXISTS);
  rb_ldap_define_err_code (LDAP_NO_OBJECT_CLASS_MODS);
  rb_ldap_define_err_code (LDAP_RESULTS_TOO_LARGE);
  rb_ldap_define_err_code (LDAP_OTHER);
  rb_ldap_define_err_code (LDAP_SERVER_DOWN);
  rb_ldap_define_err_code (LDAP_LOCAL_ERROR);
  rb_ldap_define_err_code (LDAP_ENCODING_ERROR);
  rb_ldap_define_err_code (LDAP_DECODING_ERROR);
  rb_ldap_define_err_code (LDAP_TIMEOUT);
  rb_ldap_define_err_code (LDAP_AUTH_UNKNOWN);
  rb_ldap_define_err_code (LDAP_FILTER_ERROR);
  rb_ldap_define_err_code (LDAP_USER_CANCELLED);
  rb_ldap_define_err_code (LDAP_PARAM_ERROR);
  rb_ldap_define_err_code (LDAP_NO_MEMORY);
  /* rb_ldap_define_err_code(LDAP_CONNECT_ERROR); */
#undef rb_ldap_define_err_code

#define rb_ldap_define_opt(code) rb_define_const(rb_mLDAP,#code,INT2NUM((int)code))
#ifdef LDAP_OPT_ON
  rb_ldap_define_opt (LDAP_OPT_ON);
#endif
#ifdef LDAP_OPT_OFF
  rb_ldap_define_opt (LDAP_OPT_OFF);
#endif
#ifdef LDAP_OPT_DESC
  rb_ldap_define_opt (LDAP_OPT_DESC);
#endif
#ifdef LDAP_OPT_DEREF
  rb_ldap_define_opt (LDAP_OPT_DEREF);
#endif
#ifdef LDAP_OPT_SIZELIMIT
  rb_ldap_define_opt (LDAP_OPT_SIZELIMIT);
#endif
#ifdef LDAP_OPT_TIMELIMIT
  rb_ldap_define_opt (LDAP_OPT_TIMELIMIT);
#endif
#ifdef LDAP_OPT_THREAD_FN_PTRS
  rb_ldap_define_opt (LDAP_OPT_THREAD_FN_PTRS);
#endif
#ifdef LDAP_OPT_REBIND_FN
  rb_ldap_define_opt (LDAP_OPT_REBIND_FN);
#endif
#ifdef LDAP_OPT_REBIND_ARG
  rb_ldap_define_opt (LDAP_OPT_REBIND_ARG);
#endif
#ifdef LDAP_OPT_REFERRALS
  rb_ldap_define_opt (LDAP_OPT_REFERRALS);
#endif
#ifdef LDAP_OPT_RESTART
  rb_ldap_define_opt (LDAP_OPT_RESTART);
#endif
#ifdef LDAP_OPT_SSL
  rb_ldap_define_opt (LDAP_OPT_SSL);
#endif
#ifdef LDAP_OPT_IO_FN_PTRS
  rb_ldap_define_opt (LDAP_OPT_IO_FN_PTRS);
#endif
#ifdef LDAP_OPT_CACHE_FN_PTRS
  rb_ldap_define_opt (LDAP_OPT_CACHE_FN_PTRS);
#endif
#ifdef LDAP_OPT_CACHE_STRATEGY
  rb_ldap_define_opt (LDAP_OPT_CACHE_STRATEGY);
#endif
#ifdef LDAP_OPT_CACHE_ENABLE
  rb_ldap_define_opt (LDAP_OPT_CACHE_ENABLE);
#endif
#ifdef LDAP_OPT_REFERRAL_HOP_LIMIT
  rb_ldap_define_opt (LDAP_OPT_REFERRAL_HOP_LIMIT);
#endif
#ifdef LDAP_OPT_PROTOCOL_VERSION
  rb_ldap_define_opt (LDAP_OPT_PROTOCOL_VERSION);
#endif
#ifdef LDAP_OPT_SERVER_CONTROLS
  rb_ldap_define_opt (LDAP_OPT_SERVER_CONTROLS);
#endif
#ifdef LDAP_OPT_CLIENT_CONTROLS
  rb_ldap_define_opt (LDAP_OPT_CLIENT_CONTROLS);
#endif
#ifdef LDAP_OPT_PREFERRED_LANGUAGE
  rb_ldap_define_opt (LDAP_OPT_PREFERRED_LANGUAGE);
#endif
#ifdef LDAP_OPT_API_INFO
  rb_ldap_define_opt (LDAP_OPT_API_INFO);
#endif
#ifdef LDAP_OPT_API_FEATURE_INFO
  rb_ldap_define_opt (LDAP_OPT_API_FEATURE_INFO);
#endif
#ifdef LDAP_OPT_HOST_NAME
  rb_ldap_define_opt (LDAP_OPT_HOST_NAME);
#endif

#ifdef USE_OPENLDAP2		/* OpenLDAP TLS,SASL options */
#ifdef LDAP_OPT_X_TLS_CACERTFILE
  rb_ldap_define_opt (LDAP_OPT_X_TLS_CACERTFILE);
#endif
#ifdef LDAP_OPT_X_TLS_CACERTDIR
  rb_ldap_define_opt (LDAP_OPT_X_TLS_CACERTDIR);
#endif
#ifdef LDAP_OPT_X_TLS_CERT
  rb_ldap_define_opt (LDAP_OPT_X_TLS_CERT);
#endif
#ifdef LDAP_OPT_X_TLS_CERTFILE
  rb_ldap_define_opt (LDAP_OPT_X_TLS_CERTFILE);
#endif
#ifdef LDAP_OPT_X_TLS_KEYFILE
  rb_ldap_define_opt (LDAP_OPT_X_TLS_KEYFILE);
#endif
#ifdef LDAP_OPT_X_TLS_REQUIRE_CERT
  rb_ldap_define_opt (LDAP_OPT_X_TLS_REQUIRE_CERT);
#endif
#ifdef LDAP_OPT_X_TLS
  rb_ldap_define_opt (LDAP_OPT_X_TLS);
#endif
#ifdef LDAP_OPT_X_TLS_PROTOCOL
  rb_ldap_define_opt (LDAP_OPT_X_TLS_PROTOCOL);
#endif
#ifdef LDAP_OPT_X_TLS_CIPHER_SUITE
  rb_ldap_define_opt (LDAP_OPT_X_TLS_CIPHER_SUITE);
#endif
#ifdef LDAP_OPT_X_TLS_RANDOM_FILE
  rb_ldap_define_opt (LDAP_OPT_X_TLS_RANDOM_FILE);
#endif
#ifdef LDAP_OPT_X_TLS_NEVER
  rb_ldap_define_opt (LDAP_OPT_X_TLS_NEVER);
#endif
#ifdef LDAP_OPT_X_TLS_HARD
  rb_ldap_define_opt (LDAP_OPT_X_TLS_HARD);
#endif
#ifdef LDAP_OPT_X_TLS_DEMAND
  rb_ldap_define_opt (LDAP_OPT_X_TLS_DEMAND);
#endif
#ifdef LDAP_OPT_X_TLS_ALLOW
  rb_ldap_define_opt (LDAP_OPT_X_TLS_ALLOW);
#endif
#ifdef LDAP_OPT_X_TLS_TRY
  rb_ldap_define_opt (LDAP_OPT_X_TLS_TRY);
#endif
#ifdef LDAP_OPT_X_SASL_MECH
  rb_ldap_define_opt (LDAP_OPT_X_SASL_MECH);
#endif
#ifdef LDAP_OPT_X_SASL_REALM
  rb_ldap_define_opt (LDAP_OPT_X_SASL_REALM);
#endif
#ifdef LDAP_OPT_X_SASL_AUTHCID
  rb_ldap_define_opt (LDAP_OPT_X_SASL_AUTHCID);
#endif
#ifdef LDAP_OPT_X_SASL_AUTHZID
  rb_ldap_define_opt (LDAP_OPT_X_SASL_AUTHZID);
#endif
#ifdef LDAP_OPT_X_SASL_SSF
  rb_ldap_define_opt (LDAP_OPT_X_SASL_SSF);
#endif
#ifdef LDAP_OPT_X_SASL_SSF_EXTERNAL
  rb_ldap_define_opt (LDAP_OPT_X_SASL_SSF_EXTERNAL);
#endif
#ifdef LDAP_OPT_X_SASL_SECPROPS
  rb_ldap_define_opt (LDAP_OPT_X_SASL_SECPROPS);
#endif
#ifdef LDAP_OPT_X_SASL_SSF_MIN
  rb_ldap_define_opt (LDAP_OPT_X_SASL_SSF_MIN);
#endif
#ifdef LDAP_OPT_X_SASL_SSF_MAX
  rb_ldap_define_opt (LDAP_OPT_X_SASL_SSF_MAX);
#endif
#ifdef LDAP_OPT_X_SASL_MAXBUFSIZE
  rb_ldap_define_opt (LDAP_OPT_X_SASL_MAXBUFSIZE);
#endif
#endif /* USE_OPENLDAP2 */


#undef rb_ldap_define_opt

  /* these constants indicate search scopes */
#define rb_ldap_define_scope(scope) rb_define_const(rb_mLDAP,#scope,INT2NUM(scope))
  rb_ldap_define_scope (LDAP_SCOPE_BASE);
  rb_ldap_define_scope (LDAP_SCOPE_SUBTREE);
  rb_ldap_define_scope (LDAP_SCOPE_ONELEVEL);
#undef rb_ldap_define_scope

#define rb_ldap_define_deref(x) rb_define_const(rb_mLDAP,#x,INT2NUM(x))
#ifdef LDAP_DEREF_NEVER
  rb_ldap_define_deref (LDAP_DEREF_NEVER);
#endif
#ifdef LDAP_DEREF_SEARCHING
  rb_ldap_define_deref (LDAP_DEREF_SEARCHING);
#endif
#ifdef LDAP_DEREF_FINDING
  rb_ldap_define_deref (LDAP_DEREF_FINDING);
#endif
#ifdef LDAP_DEREF_ALWAYS
  rb_ldap_define_deref (LDAP_DEREF_ALWAYS);
#endif
#undef rb_ldap_define_deref

#define rb_ldap_define_sasl_mech(c) \
        (c ? rb_define_const(rb_mLDAP,#c,rb_str_new2(c)) : rb_define_const(rb_mLDAP,#c,Qnil))
#ifdef LDAP_SASL_SIMPLE
  rb_ldap_define_sasl_mech (LDAP_SASL_SIMPLE);
#endif
#undef rb_ldap_define_sasl_mech

#define rb_ldap_define_auth_method(c) rb_define_const(rb_mLDAP,#c,INT2NUM(c))
  rb_ldap_define_auth_method (LDAP_AUTH_NONE);
  rb_ldap_define_auth_method (LDAP_AUTH_SIMPLE);
#ifdef LDAP_AUTH_KRBV41
  rb_ldap_define_auth_method (LDAP_AUTH_KRBV41);
#endif
#ifdef LDAP_AUTH_KRBV42
  rb_ldap_define_auth_method (LDAP_AUTH_KRBV42);
#endif
#ifdef LDAP_AUTH_SASL
  rb_ldap_define_auth_method (LDAP_AUTH_SASL);
#endif
#ifdef LDAP_KRBV4
  rb_ldap_define_auth_method (LDAP_KRBV4);
#endif
  /* wldap32.h */
#ifdef LDAP_AUTH_OTHERKIND
  rb_ldap_define_auth_method (LDAP_AUTH_OTHERKIND);
#endif
#ifdef LDAP_AUTH_DPA
  rb_ldap_define_auth_method (LDAP_AUTH_DPA);
#endif
#ifdef LDAP_AUTH_MSN
  rb_ldap_define_auth_method (LDAP_AUTH_MSN);
#endif
#ifdef LDAP_AUTH_NEGOTIATE
  rb_ldap_define_auth_method (LDAP_AUTH_NEGOTIATE);
#endif
#ifdef LDAP_AUTH_NTLM
  rb_ldap_define_auth_method (LDAP_AUTH_NTLM);
#endif
#ifdef LDAP_AUTH_SICILY
  rb_ldap_define_auth_method (LDAP_AUTH_SICILY);
#endif
#ifdef LDAP_AUTH_SSPI
  rb_ldap_define_auth_method (LDAP_AUTH_SSPI);
#endif
#undef rb_ldap_define_auth_method

#ifdef LDAP_CONTROL_PAGEDRESULTS
  rb_define_const (rb_mLDAP, "LDAP_CONTROL_PAGEDRESULTS",
		   rb_str_new2 (LDAP_CONTROL_PAGEDRESULTS));
#endif

#define rb_ldap_define_const(c) rb_define_const(rb_mLDAP,#c,INT2NUM(c))
  rb_ldap_define_const (LDAP_MOD_ADD);
  rb_ldap_define_const (LDAP_MOD_DELETE);
  rb_ldap_define_const (LDAP_MOD_REPLACE);
  rb_ldap_define_const (LDAP_MOD_BVALUES);
#ifdef LDAP_MOD_INCREMENT
  /*
   * See http://www.ietf.org/internet-drafts/draft-zeilenga-ldap-incr-00.txt
   */
  rb_ldap_define_const (LDAP_MOD_INCREMENT);
#endif
#ifdef LDAP_MOD_OP
  rb_ldap_define_const (LDAP_MOD_OP);
#endif
#undef rb_ldap_define_const

  Init_ldap_conn ();
  Init_ldap_sslconn ();
  Init_ldap_saslconn ();
  Init_ldap_entry ();
  Init_ldap_mod ();
  Init_ldap_misc ();
}
