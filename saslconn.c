/*
 * saslconn.c
 * $Id: saslconn.c,v 1.25 2006/02/13 17:20:32 ianmacd Exp $
 */

#include "ruby.h"
#include "rbldap.h"
#if defined(HAVE_SYS_TIME_H)
# include <sys/time.h>
#endif
#if defined(HAVE_UNISTD_H)
# include <unistd.h>
#endif

extern VALUE rb_ldap_conn_initialize (int argc, VALUE argv[], VALUE self);
extern VALUE rb_ldap_conn_rebind (VALUE self);

#if defined(HAVE_LDAP_SASL_BIND_S)
int
rb_ldap_sasl_interaction (LDAP * ld, unsigned flags, void *defaults, void *in)
{
  /* not implemented */
  return LDAP_SUCCESS;
}

/*
 * call-seq:
 * conn.sasl_bind(dn=nil, mech=nil, cred=nil, sctrls=nil, cctrls=nil)  => self
 * conn.sasl_bind(dn=nil, mech=nil, cred=nil, sctrls=nil, cctrls=nil)
 *   { |conn| }  => nil
 *
 * Bind an LDAP connection, using the DN, +dn+, the mechanism, +mech+, and the
 * credential, +cred+.
 *
 * +sctrls+ is an array of server controls, whilst +cctrls+ is an array of
 * client controls.
 *
 * and the bind method, +method+. If a block is given, +self+ is yielded to
 * the block.
 */
VALUE
rb_ldap_conn_sasl_bind (int argc, VALUE argv[], VALUE self)
{
  RB_LDAP_DATA *ldapdata;

  VALUE arg1, arg2, arg3, arg4, arg5;
  int version;
  char *dn = NULL;
  char *mechanism = NULL;
  struct berval *cred = ALLOCA_N (struct berval, 1);
  LDAPControl **serverctrls = NULL;
  LDAPControl **clientctrls = NULL;

  /*
  struct berval *servercred = NULL;
  char *sasl_realm = NULL;
  char *sasl_authc_id = NULL;
  char *sasl_authz_id = NULL;
  char *sasl_secprops = NULL;
  struct berval passwd = { 0, NULL };
  */

  unsigned sasl_flags = LDAP_SASL_AUTOMATIC;

  Data_Get_Struct (self, RB_LDAP_DATA, ldapdata);
  if (!ldapdata->ldap)
    {
      if (rb_iv_get (self, "@args") != Qnil)
	{
	  rb_ldap_conn_rebind (self);
	  GET_LDAP_DATA (self, ldapdata);
	}
      else
	{
	  rb_raise (rb_eLDAP_InvalidDataError,
		    "The LDAP handler has already unbound.");
	}
    }

  if (ldapdata->bind)
    {
      rb_raise (rb_eLDAP_Error, "already bound.");
    };
  switch (rb_scan_args (argc, argv, "23", &arg1, &arg2, &arg3, &arg4, &arg5))
    {
    case 2:			/* don't need the cred for GSSAPI */
      dn = StringValuePtr (arg1);
      mechanism = StringValuePtr (arg2);
      serverctrls = NULL;
      clientctrls = NULL;
      if (rb_iv_get (self, "@sasl_quiet") == Qtrue)
	sasl_flags = LDAP_SASL_QUIET;
      break;
    case 3:
      dn = StringValuePtr (arg1);
      mechanism = StringValuePtr (arg2);
      cred->bv_val = StringValueCStr (arg3);
      cred->bv_len = RSTRING (arg3)->len;
      break;
    case 4:
      dn = StringValuePtr (arg1);
      mechanism = StringValuePtr (arg2);
      cred->bv_val = StringValueCStr (arg3);
      cred->bv_len = RSTRING (arg3)->len;
      serverctrls = rb_ldap_get_controls (arg4);
      break;
    case 5:
      dn = StringValuePtr (arg1);
      mechanism = StringValuePtr (arg2);
      cred->bv_val = StringValueCStr (arg3);
      cred->bv_len = RSTRING (arg3)->len;
      serverctrls = rb_ldap_get_controls (arg4);
      clientctrls = rb_ldap_get_controls (arg5);
      break;
    default:
      rb_bug ("rb_ldap_conn_bind_s");
    }

  ldap_get_option (ldapdata->ldap, LDAP_OPT_PROTOCOL_VERSION, &version);
  if (version < LDAP_VERSION3)
    {
      version = LDAP_VERSION3;
      ldapdata->err =
	ldap_set_option (ldapdata->ldap, LDAP_OPT_PROTOCOL_VERSION, &version);
      Check_LDAP_Result (ldapdata->err);
    }

  /* the following works for GSSAPI, at least */
  ldapdata->err =
    ldap_sasl_interactive_bind_s (ldapdata->ldap, dn, mechanism,
				  serverctrls, clientctrls, sasl_flags,
				  rb_ldap_sasl_interaction, NULL);

  if (ldapdata->err == LDAP_SASL_BIND_IN_PROGRESS)
    {
      rb_raise (rb_eNotImpError,
		"SASL authentication is not fully supported.");
      /* How can I implement this with portability? */
      /* 
         VALUE scred;
	 scred = rb_tainted_str_new(servercred->bv_val,
         servercred->bv_len);
      */
    }
  else
    {
      Check_LDAP_Result (ldapdata->err);
      ldapdata->bind = 1;
    }

  if (rb_block_given_p ())
    {
      rb_ensure (rb_yield, self, rb_ldap_conn_unbind, self);
      return Qnil;
    }
  else
    {
      return self;
    };
}

#else /* HAVE_LDAP_SASL_BIND_S */

VALUE
rb_ldap_conn_sasl_bind (int argc, VALUE argv[], VALUE self)
{
  rb_notimplement ();
}

#endif /* HAVE_LDAP_SASL_BIND_S */

void
Init_ldap_saslconn ()
{
  rb_define_method (rb_cLDAP_Conn, "sasl_bind", rb_ldap_conn_sasl_bind, -1);
}
