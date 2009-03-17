/*
 * sslconn.c
 * $Id: sslconn.c,v 1.18 2006/04/19 22:13:26 ianmacd Exp $
 */

#include "ruby.h"
#include "rbldap.h"
#if defined(HAVE_SYS_TIME_H)
# include <sys/time.h>
#endif
#if defined(HAVE_UNISTD_H)
# include <unistd.h>
#endif

#if defined(HAVE_LDAP_START_TLS_S)
# define USE_OPENLDAP_SSLCONN
#elif defined(HAVE_LDAPSSL_INIT)
# define USE_NSSLDAP_SSLCONN
#elif defined(HAVE_LDAP_SSLINIT)
# define USE_WLDAP32_SSLCONN
#endif

VALUE rb_cLDAP_SSLConn;

#ifdef USE_OPENLDAP_SSLCONN
static VALUE
rb_openldap_sslconn_initialize (int argc, VALUE argv[], VALUE self)
{
  RB_LDAP_DATA *ldapdata;
  LDAP *cldap;
  char *chost = NULL;
  int cport = LDAP_PORT;

  VALUE arg1, arg2, arg3, arg4, arg5;

  LDAPControl **serverctrls = NULL;
  LDAPControl **clientctrls = NULL;
  int version;
  int start_tls;


  Data_Get_Struct (self, RB_LDAP_DATA, ldapdata);
  if (ldapdata->ldap)
    return Qnil;

  switch (rb_scan_args (argc, argv, "05", &arg1, &arg2, &arg3, &arg4, &arg5))
    {
    case 0:
      chost = ALLOCA_N (char, strlen ("localhost") + 1);
      strcpy (chost, "localhost");
      cport = LDAP_PORT;
      start_tls = 0;
      break;
    case 1:
      chost = StringValueCStr (arg1);
      cport = LDAP_PORT;
      start_tls = 0;
      break;
    case 2:
      chost = StringValueCStr (arg1);
      cport = NUM2INT (arg2);
      start_tls = 0;
      break;
    case 3:
      chost = StringValueCStr (arg1);
      cport = NUM2INT (arg2);
      start_tls = (arg3 == Qtrue) ? 1 : 0;
      break;
    case 4:
      chost = StringValueCStr (arg1);
      cport = NUM2INT (arg2);
      start_tls = (arg3 == Qtrue) ? 1 : 0;
      serverctrls = rb_ldap_get_controls (arg4);
      break;
    case 5:
      chost = StringValueCStr (arg1);
      cport = NUM2INT (arg2);
      start_tls = (arg3 == Qtrue) ? 1 : 0;
      serverctrls = rb_ldap_get_controls (arg4);
      clientctrls = rb_ldap_get_controls (arg5);
      break;
    default:
      rb_bug ("rb_ldap_conn_new");
    }

  cldap = ldap_init (chost, cport);
  if (!cldap)
    rb_raise (rb_eLDAP_ResultError, "can't initialise an LDAP session");

  ldapdata->ldap = cldap;

  if (rb_block_given_p ())
    {
      rb_yield (self);
    }

  ldap_get_option (cldap, LDAP_OPT_PROTOCOL_VERSION, &version);
  if (version < LDAP_VERSION3)
    {
      version = LDAP_VERSION3;
      ldapdata->err =
	ldap_set_option (cldap, LDAP_OPT_PROTOCOL_VERSION, &version);
      Check_LDAP_Result (ldapdata->err);
    }

  if (start_tls)
    {
      ldapdata->err = ldap_start_tls_s (cldap, serverctrls, clientctrls);
      Check_LDAP_Result (ldapdata->err);
    }
  else
    {
      int opt = LDAP_OPT_X_TLS_HARD;
      ldapdata->err = ldap_set_option (cldap, LDAP_OPT_X_TLS, &opt);
      Check_LDAP_Result (ldapdata->err);
    }

  rb_iv_set (self, "@args", rb_ary_new4 (argc, argv));
  rb_iv_set (self, "@sasl_quiet", Qfalse);

  return Qnil;
}
#endif /* USE_OPENLDAP_SSLCONN */


#ifdef USE_NSSLDAP_SSLCONN
static VALUE
rb_nssldap_sslconn_initialize (int argc, VALUE argv[], VALUE self)
{
  RB_LDAP_DATA *ldapdata;
  LDAP *cldap;
  char *chost = NULL;
  char *certpath = NULL;
  int cport = LDAP_PORT;
  int csecure = 0;

  VALUE arg1, arg2, arg3, arg4;

  Data_Get_Struct (self, RB_LDAP_DATA, ldapdata);
  if (ldapdata->ldap)
    return Qnil;

  switch (rb_scan_args (argc, argv, "04", &arg1, &arg2, &arg3, &arg4))
    {
    case 0:
      chost = ALLOCA_N (char, strlen ("localhost") + 1);
      strcpy (chost, "localhost");
      cport = LDAP_PORT;
      csecure = 0;
      certpath = NULL;
      break;
    case 1:
      chost = StringValueCStr (arg1);
      cport = LDAP_PORT;
      csecure = 0;
      certpath = NULL;
      break;
    case 2:
      chost = StringValueCStr (arg1);
      cport = NUM2INT (arg2);
      csecure = 0;
      certpath = NULL;
      break;
    case 3:
      chost = StringValueCStr (arg1);
      cport = NUM2INT (arg2);
      csecure = (arg3 == Qtrue) ? 1 : 0;
      certpath = NULL;
      break;
    case 4:
      chost = StringValueCStr (arg1);
      cport = NUM2INT (arg2);
      csecure = (arg3 == Qtrue) ? 1 : 0;
      certpath = (arg4 == Qnil) ? NULL : StringValueCStr (arg4);
      break;
    default:
      rb_bug ("rb_ldap_conn_new");
    }

  /***
    ldapssl_client_init():
     http://docs.iplanet.com/docs/manuals/dirsdk/csdk41/html/function.htm#25963
     ldapssl_client_authinit():
     http://docs.iplanet.com/docs/manuals/dirsdk/csdk41/html/function.htm#26024
  ***/
  ldapssl_client_init (certpath, NULL);
  cldap = ldapssl_init (chost, cport, csecure);
  ldapdata->ldap = cldap;

  rb_iv_set (self, "@args", Qnil);

  return Qnil;
}
#endif /* USE_NSSLDAP_SSLCONN */

#if defined(USE_WLDAP32_SSLCONN)
static VALUE
rb_wldap32_sslconn_initialize (int argc, VALUE argv[], VALUE self)
{
  RB_LDAP_DATA *ldapdata;
  LDAP *cldap;
  char *chost;
  int cport;
  int csecure;
  int version;

  VALUE arg1, arg2, arg3;

  Data_Get_Struct (self, RB_LDAP_DATA, ldapdata);
  if (ldapdata->ldap)
    return Qnil;

  switch (rb_scan_args (argc, argv, "02", &arg1, &arg2, &arg3))
    {
    case 0:
      chost = ALLOCA_N (char, strlen ("localhost") + 1);
      strcpy (chost, "localhost");
      cport = LDAP_PORT;
      csecure = 1;
      break;
    case 1:
      chost = StringValueCStr (arg1);
      cport = LDAP_PORT;
      csecure = 1;
      break;
    case 2:
      chost = StringValueCStr (arg1);
      cport = NUM2INT (arg2);
      csecure = 1;
      break;
    case 3:
      chost = StringValueCStr (arg1);
      cport = NUM2INT (arg2);
      csecure = (arg3 == Qtrue) ? 1 : 0;
      break;
    default:
      rb_bug ("rb_ldap_conn_new");
    }

  cldap = ldap_sslinit (chost, cport, csecure);
  ldapdata->ldap = cldap;

#if defined(HAVE_LDAP_GET_OPTION) && defined(HAVE_LDAP_SET_OPTION)
  ldap_get_option (cldap, LDAP_OPT_PROTOCOL_VERSION, &version);
  if (version < LDAP_VERSION3)
    {
      version = LDAP_VERSION3;
      ldapdata->err =
	ldap_set_option (cldap, LDAP_OPT_PROTOCOL_VERSION, &version);
      Check_LDAP_Result (ldapdata->err);
    }
#endif

  rb_iv_set (self, "@args", Qnil);

  return Qnil;
}

VALUE
rb_ldap_sslconn_bind_f (int argc, VALUE argv[], VALUE self,
			VALUE (*rb_ldap_sslconn_bind_func) (int, VALUE[],
							    VALUE))
{
  RB_LDAP_DATA *ldapdata;

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

  ldapdata->err = ldap_connect (ldapdata->ldap, NULL);
  Check_LDAP_Result (ldapdata->err);

  return rb_ldap_sslconn_bind_func (argc, argv, self);
}

/*
 * call-seq:
 * conn.bind(dn=nil, password=nil, method=LDAP::LDAP_AUTH_SIMPLE)  => self
 * conn.bind(dn=nil, password=nil, method=LDAP::LDAP_AUTH_SIMPLE)
 *   { |conn| }  => self
 *
 * Bind an LDAP connection, using the DN, +dn+, the credential, +password+,
 * and the bind method, +method+. If a block is given, +self+ is yielded to
 * the block.
 */
VALUE
rb_ldap_sslconn_bind_s (int argc, VALUE argv[], VALUE self)
{
  return rb_ldap_sslconn_bind_f (argc, argv, self, rb_ldap_conn_bind_s);
}

/*
 * call-seq:
 * conn.simple_bind(dn=nil, password=nil)  => self
 * conn.simple_bind(dn=nil, password=nil) { |conn| }  => self
 *
 * Bind an LDAP connection, using the DN, +dn+, and the credential, +password+.
 * If a block is given, +self+ is yielded to the block.
 */
VALUE
rb_ldap_sslconn_simple_bind_s (int argc, VALUE argv[], VALUE self)
{
  return rb_ldap_sslconn_bind_f (argc, argv, self,
				 rb_ldap_conn_simple_bind_s);
}
#endif /* USE_WLDAP32_SSLCONN */

/*
 * call-seq:
 * LDAP::SSLConn.new(host='localhost', port=LDAP_PORT,
 *                   start_tls=false, sctrls=nil, cctrls=nil)
 *   => LDAP::SSLConn
 * LDAP::SSLConn.new(host='localhost', port=LDAP_PORT,
 *                   start_tls=false, sctrls=nil, cctrls=nil) { |conn| }
 *   => LDAP::SSLConn
 *
 * Return a new LDAP::SSLConn connection to the server, +host+, on port +port+.
 * If +start_tls+ is *true*, START_TLS will be used to establish the
 * connection, automatically setting the LDAP protocol version to v3 if it is
 * not already set.
 *
 * +sctrls+ is an array of server controls, whilst +cctrls+ is an array of
 * client controls.
 */
VALUE
rb_ldap_sslconn_initialize (int argc, VALUE argv[], VALUE self)
{
#if defined(USE_OPENLDAP_SSLCONN)
  return rb_openldap_sslconn_initialize (argc, argv, self);
#elif defined(USE_NSSLDAP_SSLCONN)
  return rb_nssldap_sslconn_initialize (argc, argv, self);
#elif defined(USE_WLDAP32_SSLCONN)
  return rb_wldap32_sslconn_initialize (argc, argv, self);
#else
  rb_notimplement ();
#endif
}

/* :nodoc: */
VALUE
rb_ldap_sslconn_s_open (int argc, VALUE argv[], VALUE klass)
{
  rb_notimplement ();
}

/* Document-class: LDAP::SSLConn
 *
 * Create and manipulate encrypted LDAP connections. LDAP::SSLConn is a
 * subclass of LDAP::Conn and so has access to the same methods, except for
 * LDAP::SSLConn.open, which is not implemented.
 */
void
Init_ldap_sslconn ()
{
  rb_cLDAP_SSLConn =
    rb_define_class_under (rb_mLDAP, "SSLConn", rb_cLDAP_Conn);
  rb_define_singleton_method (rb_cLDAP_SSLConn, "open",
			      rb_ldap_sslconn_s_open, -1);
  rb_define_method (rb_cLDAP_SSLConn, "initialize",
		    rb_ldap_sslconn_initialize, -1);
#ifdef USE_WLDAP32_SSLCONN
  rb_define_method (rb_cLDAP_SSLConn, "bind", rb_ldap_sslconn_bind_s, -1);
  rb_define_method (rb_cLDAP_SSLConn, "simple_bind",
		    rb_ldap_sslconn_simple_bind_s, -1);
#endif
}
