/*
 * conn.c
 * $Id: conn.c,v 1.51 2006/08/01 00:07:53 ianmacd Exp $
 */

#include "ruby.h"
#include "rbldap.h"
#if defined(HAVE_SYS_TIME_H)
# include <sys/time.h>
#endif
#if defined(HAVE_UNISTD_H)
# include <unistd.h>
#endif

/* RDoc needs the following bogus code to find the parent module:
 *
 * rb_mLDAP = rb_define_module ("LDAP");
 */

static VALUE rb_ldap_sort_obj = Qnil;
extern VALUE rb_ldap_control_new2 (LDAPControl * ctl);
extern VALUE rb_ldap_sslconn_initialize (int argc, VALUE argv[], VALUE self);
extern VALUE rb_ldap_conn_rebind (VALUE self);

VALUE rb_cLDAP_Conn;

static void
rb_ldap_conn_free (RB_LDAP_DATA * ldapdata)
{
  if (ldapdata->ldap && ldapdata->bind)
    {
      ldap_unbind (ldapdata->ldap);
    };
};

static void
rb_ldap_conn_mark (RB_LDAP_DATA * ldapdata)
{
  /* empty */
};

VALUE
rb_ldap_conn_new (VALUE klass, LDAP * cldap)
{
  VALUE conn;
  RB_LDAP_DATA *ldapdata;

  conn = Data_Make_Struct (klass, RB_LDAP_DATA,
			   rb_ldap_conn_mark, rb_ldap_conn_free, ldapdata);
  ldapdata->ldap = cldap;
  ldapdata->err = 0;
  ldapdata->bind = 0;

  return conn;
};

VALUE
rb_ldap_conn_s_allocate (VALUE klass)
{
  return rb_ldap_conn_new (klass, (LDAP *) 0);
}

/*
 * call-seq:
 * LDAP::Conn.new(host='localhost', port=LDAP_PORT)  => LDAP::Conn
 *
 * Return a new LDAP::Conn connection to the server, +host+, on port +port+.
 */
VALUE
rb_ldap_conn_initialize (int argc, VALUE argv[], VALUE self)
{
  LDAP *cldap;
  char *chost;
  int cport;
  int was_verbose = Qfalse;
  RB_LDAP_DATA *ldapdata;

  VALUE host, port;

  Data_Get_Struct (self, RB_LDAP_DATA, ldapdata);
  if (ldapdata->ldap)
    {
      return Qnil;
    }

  switch (rb_scan_args (argc, argv, "02", &host, &port))
    {
    case 0:
      chost = ALLOCA_N (char, strlen ("localhost") + 1);
      strcpy (chost, "localhost");
      cport = LDAP_PORT;
      break;
    case 1:
      chost = StringValueCStr (host);
      cport = LDAP_PORT;
      break;
    case 2:
      chost = StringValueCStr (host);
      cport = NUM2INT (port);
      break;
    default:
      rb_bug ("rb_ldap_conn_new");
    };

  cldap = ldap_init (chost, cport);
  if (!cldap)
    rb_raise (rb_eLDAP_ResultError, "can't initialise an LDAP session");
  ldapdata->ldap = cldap;

  rb_iv_set (self, "@args", rb_ary_new4 (argc, argv));

  /* Silence warning that next rb_iv_get produces. */
  if (ruby_verbose == Qtrue)
    {
      was_verbose = Qtrue;
      ruby_verbose = Qfalse;
    }

  if (rb_iv_get (self, "@sasl_quiet") != Qtrue)
    rb_iv_set (self, "@sasl_quiet", Qfalse);
  if (was_verbose == Qtrue)
    ruby_verbose = Qtrue;

  return Qnil;
};

/*
 * call-seq:
 * LDAP::Conn.open(host='localhost', port=LDAP_PORT)  => LDAP::Conn
 *
 * Return a new LDAP::Conn connection to the server, +host+, on port +port+.
 */
VALUE
rb_ldap_conn_s_open (int argc, VALUE argv[], VALUE klass)
{
  LDAP *cldap;
  char *chost;
  int cport;

  VALUE host, port;
  VALUE conn;

  switch (rb_scan_args (argc, argv, "02", &host, &port))
    {
    case 0:
      chost = ALLOCA_N (char, strlen ("localhost") + 1);
      strcpy (chost, "localhost");
      cport = LDAP_PORT;
      break;
    case 1:
      chost = StringValueCStr (host);
      cport = LDAP_PORT;
      break;
    case 2:
      chost = StringValueCStr (host);
      cport = NUM2INT (port);
      break;
    default:
      rb_bug ("rb_ldap_conn_new");
    };

  cldap = ldap_open (chost, cport);
  if (!cldap)
    rb_raise (rb_eLDAP_ResultError, "can't open an LDAP session");
  conn = rb_ldap_conn_new (klass, cldap);

  return conn;
};

/*
 * call-seq:
 * conn.start_tls  => nil
 *
 * Initiate START_TLS for the connection, +conn+.
 */
VALUE
rb_ldap_conn_start_tls_s (int argc, VALUE argv[], VALUE self)
{
#ifdef HAVE_LDAP_START_TLS_S
  VALUE arg1, arg2;
  RB_LDAP_DATA *ldapdata;
  LDAPControl **serverctrls;
  LDAPControl **clientctrls;

  switch (rb_scan_args (argc, argv, "02", &arg1, &arg2))
    {
    case 0:
      serverctrls = NULL;
      clientctrls = NULL;
      break;
    case 1:
    case 2:
      rb_notimplement ();
    default:
      rb_bug ("rb_ldap_conn_start_tls_s");
    };

  GET_LDAP_DATA (self, ldapdata);
  ldapdata->err = ldap_start_tls_s (ldapdata->ldap, serverctrls, clientctrls);
  Check_LDAP_Result (ldapdata->err);
#else
  rb_notimplement ();
#endif
  return Qnil;
};

VALUE
rb_ldap_conn_rebind (VALUE self)
{
  VALUE ary = rb_iv_get (self, "@args");

  if (rb_obj_is_kind_of (self, rb_cLDAP_SSLConn) == Qtrue)
    return rb_ldap_sslconn_initialize (RARRAY (ary)->len, RARRAY (ary)->ptr,
				       self);
  else
    return rb_ldap_conn_initialize (RARRAY (ary)->len, RARRAY (ary)->ptr,
				    self);
}

/*
 * call-seq:
 * conn.simple_bind(dn=nil, password=nil)  => self
 * conn.simple_bind(dn=nil, password=nil) { |conn| }  => nil
 *
 * Bind an LDAP connection, using the DN, +dn+, and the credential, +password+.
 * If a block is given, +self+ is yielded to the block.
 */
VALUE
rb_ldap_conn_simple_bind_s (int argc, VALUE argv[], VALUE self)
{
  RB_LDAP_DATA *ldapdata;

  VALUE arg1, arg2;
  char *dn = NULL;
  char *passwd = NULL;

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
  switch (rb_scan_args (argc, argv, "02", &arg1, &arg2))
    {
    case 0:
      break;
    case 1:
      if (arg1 == Qnil)
	{
	  dn = NULL;
	}
      else
	{
	  dn = StringValueCStr (arg1);
	}
      break;
    case 2:
      if (arg1 == Qnil)
	{
	  dn = NULL;
	}
      else
	{
	  dn = StringValueCStr (arg1);
	}
      if (arg2 == Qnil)
	{
	  passwd = NULL;
	}
      else
	{
	  passwd = StringValueCStr (arg2);
	}
      break;
    default:
      rb_bug ("rb_ldap_conn_simple_bind_s");
    }

  ldapdata->err = ldap_simple_bind_s (ldapdata->ldap, dn, passwd);
  Check_LDAP_Result (ldapdata->err);
  ldapdata->bind = 1;

  if (rb_block_given_p ())
    {
      rb_ensure (rb_yield, self, rb_ldap_conn_unbind, self);
      return Qnil;
    }
  else
    {
      return self;
    };
};

/*
 * call-seq:
 * conn.bind(dn=nil, password=nil, method=LDAP::LDAP_AUTH_SIMPLE)
 *   => self
 * conn.bind(dn=nil, password=nil, method=LDAP::LDAP_AUTH_SIMPLE)
 *   { |conn| }  => nil
 *
 * Bind an LDAP connection, using the DN, +dn+, the credential, +password+,
 * and the bind method, +method+. If a block is given, +self+ is yielded to
 * the block.
 */
VALUE
rb_ldap_conn_bind_s (int argc, VALUE argv[], VALUE self)
{
  RB_LDAP_DATA *ldapdata;

  VALUE arg1, arg2, arg3;
  char *dn = NULL;
  char *passwd = NULL;
  int method = LDAP_AUTH_SIMPLE;

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
  switch (rb_scan_args (argc, argv, "03", &arg1, &arg2, &arg3))
    {
    case 0:
      break;
    case 1:
      dn = StringValueCStr (arg1);
      break;
    case 2:
      dn = StringValueCStr (arg1);
      passwd = StringValueCStr (arg2);
      break;
    case 3:
      dn = StringValueCStr (arg1);
      passwd = StringValueCStr (arg2);
      method = NUM2INT (arg3);
      break;
    default:
      rb_bug ("rb_ldap_conn_bind_s");
    }

  ldapdata->err = ldap_bind_s (ldapdata->ldap, dn, passwd, method);
  Check_LDAP_Result (ldapdata->err);
  ldapdata->bind = 1;

  if (rb_block_given_p ())
    {
      rb_ensure (rb_yield, self, rb_ldap_conn_unbind, self);
      return Qnil;
    }
  else
    {
      return self;
    };
};

/*
 * call-seq:
 * conn.unbind  => nil
 *
 * Unbind the LDAP connection from the server.
 */
VALUE
rb_ldap_conn_unbind (VALUE self)
{
  RB_LDAP_DATA *ldapdata;

  GET_LDAP_DATA (self, ldapdata);
  ldapdata->err = ldap_unbind (ldapdata->ldap);
  ldapdata->bind = 0;
  ldapdata->ldap = NULL;
  Check_LDAP_Result (ldapdata->err);

  return Qnil;
};

/*
 * call-seq:
 * conn.bound?  => true or false
 *
 * Return *true* if the LDAP connection is still bound.
 */
VALUE
rb_ldap_conn_bound (VALUE self)
{
  RB_LDAP_DATA *ldapdata;

  Data_Get_Struct (self, RB_LDAP_DATA, ldapdata);

  return ldapdata->bind == 0 ? Qfalse : Qtrue;
};

/*
 * call-seq:
 * conn.set_option(option, data)  => self
 *
 * Set a session-wide option for this LDAP connection.
 *
 * For example:
 * 
 * <code>conn.set_option( LDAP::LDAP_OPT_PROTOCOL_VERSION, 3 )</code>
 *
 * would set the protocol of this connection to LDAPv3.
 */
VALUE
rb_ldap_conn_set_option (VALUE self, VALUE opt, VALUE data)
{
  /* ldap_set_option() is defined in IETF draft */
#ifdef HAVE_LDAP_SET_OPTION
  RB_LDAP_DATA *ldapdata;
  RB_LDAP_DATA dummy;
  int idata;
  void *optdata;
  int copt;

  if (NIL_P (self))
    {
      dummy.ldap = NULL;
      dummy.err = dummy.bind = 0;
      ldapdata = &dummy;
    }
  else
    GET_LDAP_DATA (self, ldapdata);
  copt = NUM2INT (opt);

  switch (copt)
    {
    case LDAP_OPT_REFERRALS:
      optdata = (void *) NUM2INT (data);
      break;
    case LDAP_OPT_DEREF:
    case LDAP_OPT_SIZELIMIT:
    case LDAP_OPT_TIMELIMIT:
    case LDAP_OPT_RESTART:
    case LDAP_OPT_PROTOCOL_VERSION:
      if (ldapdata->bind != 0)
	rb_raise (rb_eLDAP_ResultError,
		  "can't set LDAP protocol version after bind");
    case LDAP_OPT_ERROR_NUMBER:
#ifdef LDAP_OPT_SSL
    case LDAP_OPT_SSL:
#endif
#ifdef USE_OPENLDAP2
#ifdef LDAP_OPT_X_TLS
    case LDAP_OPT_X_TLS:
#endif
#ifdef LDAP_OPT_X_TLS_REQUIRE_CERT
    case LDAP_OPT_X_TLS_REQUIRE_CERT:
#endif
#endif
      idata = NUM2INT (data);
      optdata = &idata;
      break;
    case LDAP_OPT_HOST_NAME:
    case LDAP_OPT_ERROR_STRING:
#ifdef LDAP_OPT_MATCHED_DN
    case LDAP_OPT_MATCHED_DN:
#endif
#ifdef USE_OPENLDAP2
#ifdef LDAP_OPT_X_TLS_CACERTFILE
    case LDAP_OPT_X_TLS_CACERTFILE:
#endif
#ifdef LDAP_OPT_X_TLS_CACERTDIR
    case LDAP_OPT_X_TLS_CACERTDIR:
#endif
#ifdef LDAP_OPT_X_TLS_CERT
    case LDAP_OPT_X_TLS_CERT:
#endif
#ifdef LDAP_OPT_X_TLS_CERTFILE
    case LDAP_OPT_X_TLS_CERTFILE:
#endif
#ifdef LDAP_OPT_X_TLS_KEYFILE
    case LDAP_OPT_X_TLS_KEYFILE:
#endif
#ifdef LDAP_OPT_X_TLS_PROTOCOL
    case LDAP_OPT_X_TLS_PROTOCOL:
#endif
#ifdef LDAP_OPT_X_TLS_CIPHER_SUITE
    case LDAP_OPT_X_TLS_CIPHER_SUITE:
#endif
#ifdef LDAP_OPT_X_TLS_RANDOM_FILE
    case LDAP_OPT_X_TLS_RANDOM_FILE:
#endif
#endif
      optdata = NIL_P (data) ? NULL : StringValueCStr (data);
      break;
#ifdef LDAP_OPT_API_INFO
    case LDAP_OPT_API_INFO:
      rb_raise (rb_eLDAP_Error, "option is read-only");
      /* optdata = (void*)rb_ldap_get_apiinfo(data); */
      break;
#endif
#ifdef LDAP_OPT_SERVER_CONTROLS
    case LDAP_OPT_SERVER_CONTROLS:
      optdata = rb_ldap_get_controls (data);
      break;
#endif
    default:
      rb_notimplement ();
    }
  ldapdata->err = ldap_set_option (ldapdata->ldap, copt, optdata);
  Check_LDAP_OPT_Result (ldapdata->err);

  return self;
#else
  rb_notimplement ();
#endif
};

static VALUE
rb_ldap_conn_s_set_option (VALUE klass, VALUE opt, VALUE data)
{
  return rb_ldap_conn_set_option (Qnil, opt, data);
}

/* call-seq:
 * conn.get_option(opt)  => String
 *
 * Return the value associated with the option, +opt+.
 */
VALUE
rb_ldap_conn_get_option (VALUE self, VALUE opt)
{
#ifdef HAVE_LDAP_GET_OPTION
  RB_LDAP_DATA *ldapdata;
  static RB_LDAP_DATA dummy = { NULL, 0, 0 };
  long *data;
  int copt;
  VALUE val;

  if (NIL_P (self))
    {
      if (dummy.ldap == NULL)
	dummy.ldap = ldap_init ("", 0);
      ldapdata = &dummy;
    }
  else
    GET_LDAP_DATA (self, ldapdata);
  copt = NUM2INT (opt);

#if defined(LDAP_OPT_API_INFO) && defined(LDAP_API_INFO_VERSION)
  if (copt == LDAP_OPT_API_INFO)
    {
      LDAPAPIInfo *info;

      info = ALLOCA_N (LDAPAPIInfo, 1);
      /* This is from the Netscape SDK docs for 4.1* */
      info->ldapai_info_version = LDAP_API_INFO_VERSION;
      ldapdata->err = ldap_get_option (NULL, copt, (void *) info);
      data = (long *) info;
    }
  else
    {
      data = (void *) ALLOCA_N (char, LDAP_GET_OPT_MAX_BUFFER_SIZE);
      ldapdata->err = ldap_get_option (ldapdata->ldap, copt, (void *) data);
    }
#else
  data = (void *) ALLOCA_N (char, LDAP_GET_OPT_MAX_BUFFER_SIZE);
  ldapdata->err = ldap_get_option (ldapdata->ldap, copt, (void *) data);
#endif

  if (ldapdata->err == LDAP_OPT_SUCCESS)
    {
      switch (copt)
	{
	case LDAP_OPT_DEREF:
	case LDAP_OPT_SIZELIMIT:
	case LDAP_OPT_TIMELIMIT:
	case LDAP_OPT_REFERRALS:
	case LDAP_OPT_RESTART:
	case LDAP_OPT_PROTOCOL_VERSION:
	case LDAP_OPT_ERROR_NUMBER:
#ifdef USE_OPENLDAP2
#ifdef LDAP_OPT_X_TLS
	case LDAP_OPT_X_TLS:
#endif
#ifdef LDAP_OPT_X_TLS_REQUIRE_CERT
	case LDAP_OPT_X_TLS_REQUIRE_CERT:
#endif
#endif
	  val = INT2NUM ((int) (*data));
	  break;

	case LDAP_OPT_HOST_NAME:
	case LDAP_OPT_ERROR_STRING:
#ifdef LDAP_OPT_MATCHED_DN
	case LDAP_OPT_MATCHED_DN:
#endif
#ifdef USE_OPENLDAP2
#ifdef LDAP_OPT_X_TLS_CACERTFILE
	case LDAP_OPT_X_TLS_CACERTFILE:
#endif
#ifdef LDAP_OPT_X_TLS_CACERTDIR
	case LDAP_OPT_X_TLS_CACERTDIR:
#endif
#ifdef LDAP_OPT_X_TLS_CERT
	case LDAP_OPT_X_TLS_CERT:
#endif
#ifdef LDAP_OPT_X_TLS_CERTFILE
	case LDAP_OPT_X_TLS_CERTFILE:
#endif
#ifdef LDAP_OPT_X_TLS_KEYFILE
	case LDAP_OPT_X_TLS_KEYFILE:
#endif
#ifdef LDAP_OPT_X_TLS_PROTOCOL
	case LDAP_OPT_X_TLS_PROTOCOL:
#endif
#ifdef LDAP_OPT_X_TLS_CIPHER_SUITE
	case LDAP_OPT_X_TLS_CIPHER_SUITE:
#endif
#ifdef LDAP_OPT_X_TLS_RANDOM_FILE
	case LDAP_OPT_X_TLS_RANDOM_FILE:
#endif
#endif
	  val = (data
		 && *data) ? rb_tainted_str_new2 ((char *) (*data)) : Qnil;
	  break;
#ifdef LDAP_OPT_API_INFO
	case LDAP_OPT_API_INFO:
	  val = rb_ldap_apiinfo_new ((LDAPAPIInfo *) data);
	  break;
#endif
	default:
	  rb_notimplement ();
	};

      return val;
    }
  else
    {
      rb_raise (rb_eLDAP_Error, ldap_err2string (ldapdata->err));
    };
#else
  rb_notimplement ();
#endif
};

static VALUE
rb_ldap_conn_s_get_option (VALUE klass, VALUE opt)
{
  return rb_ldap_conn_get_option (Qnil, opt);
}

/*
 * call-seq:
 * conn.perror(msg)  => nil
 *
 * Print the text string associated with the error code of the last LDAP
 * operation. +msg+ is used to prefix the error.
 */
VALUE
rb_ldap_conn_perror (VALUE self, VALUE msg)
{
  RB_LDAP_DATA *ldapdata;
  char *cmsg;
#if (! defined(HAVE_LDAP_PERROR)) || defined(USE_NETSCAPE_SDK)
  char *str;
#endif

  GET_LDAP_DATA (self, ldapdata);
  cmsg = StringValueCStr (msg);
#if defined(HAVE_LDAP_PERROR) && (! defined(USE_NETSCAPE_SDK))
  ldap_perror (ldapdata->ldap, cmsg);
#else
  str = ldap_err2string (ldapdata->err);
  fprintf (stderr, "%s: %s\n", cmsg, str);
#endif

  return Qnil;
};

/*
 * call-seq:
 * conn.result2error(msg)  => Fixnum
 *
 * Return the error code associated with the LDAP message, +msg+.
 */
VALUE
rb_ldap_conn_result2error (VALUE self, VALUE msg)
{
  RB_LDAP_DATA *ldapdata;
  RB_LDAPENTRY_DATA *edata;
  int cdofree = 0;

  GET_LDAP_DATA (self, ldapdata);
  Check_Kind (msg, rb_cLDAP_Entry);
  GET_LDAPENTRY_DATA (msg, edata);

  ldapdata->err = ldap_result2error (ldapdata->ldap, edata->msg, cdofree);
  return INT2NUM (ldapdata->err);
};

/*
 * call-seq:
 * conn.err2string(err)  => String
 *
 * Return the text string associated with the LDAP error, +err+.
 */
VALUE
rb_ldap_conn_err2string (VALUE self, VALUE err)
{
  RB_LDAP_DATA *ldapdata;
  int c_err = NUM2INT (err);
  char *str;

  GET_LDAP_DATA (self, ldapdata);
  str = ldap_err2string (c_err);
  return (str ? rb_tainted_str_new2 (str) : Qnil);
};

VALUE
rb_ldap_conn_get_errno (VALUE self)
{
  RB_LDAP_DATA *ldapdata;
  VALUE err;

  GET_LDAP_DATA (self, ldapdata);

#ifdef USE_NETSCAPE_SDK
  cerr = ldap_get_lderrno (ldapdata->ldap, NULL, NULL);
  err = INT2NUM (cerr);
#else
# ifdef USE_OPENLDAP1
  cerr = NUM2INT (ldapdata->ldap->ld_errno);
  err = INT2NUM (cerr);
# else
  rb_notimplement ();
# endif
#endif

  return err;
};

static VALUE
rb_ldap_conn_invalidate_entry (VALUE msg)
{
  RB_LDAPENTRY_DATA *edata;
  GET_LDAPENTRY_DATA (msg, edata);
  edata->ldap = NULL;
  edata->msg = NULL;
  return Qnil;
};


static int
rb_ldap_internal_strcmp (const char *left, const char *right)
{
  VALUE res;

  if (rb_ldap_sort_obj == Qtrue)
    {
      res = rb_funcall (rb_tainted_str_new2 (left), rb_intern ("<=>"), 1,
			rb_tainted_str_new2 (right));
    }
  else if (rb_ldap_sort_obj != Qnil)
    {
      res = rb_funcall (rb_ldap_sort_obj, rb_intern ("call"), 2,
			rb_tainted_str_new2 (left),
			rb_tainted_str_new2 (right));
    }
  else
    {
      res = 0;
    };

  return INT2NUM (res);
};

static int
rb_ldap_conn_search_i (int argc, VALUE argv[], VALUE self,
		       RB_LDAP_DATA ** ldapdata, LDAPMessage ** cmsg)
{
  VALUE base, scope, filter, attrs, attrsonly, sec, usec, s_attr, s_proc;

  LDAP *cldap;
  char *cbase;
  int cscope;
  char *cfilter;
  char **cattrs;
  char *sort_attr;
  int cattrsonly;
  int i;
  struct timeval tv;

  GET_LDAP_DATA (self, (*ldapdata));
  cldap = (*ldapdata)->ldap;

  cattrs = NULL;
  cattrsonly = 0;
  tv.tv_sec = 0;
  tv.tv_usec = 0;
  sort_attr = NULL;
  rb_ldap_sort_obj = Qnil;

  switch (rb_scan_args (argc, argv, "36",
			&base, &scope, &filter, &attrs, &attrsonly, &sec,
			&usec, &s_attr, &s_proc))
    {
    case 9:
      rb_ldap_sort_obj = s_proc;	/* Ruby's GC never starts in a C function */
    case 8:
      if (rb_ldap_sort_obj == Qnil)
	{
	  rb_ldap_sort_obj = Qtrue;
	}
      sort_attr = StringValueCStr (s_attr);
    case 7:
      tv.tv_usec = NUM2INT (usec);
    case 6:
      tv.tv_sec = NUM2INT (sec);
    case 5:
      cattrsonly = (attrsonly == Qtrue) ? 1 : 0;
    case 4:
      if (TYPE (attrs) == T_NIL)
	{
	  cattrs = NULL;
	}
      else
	{
	  if (TYPE (attrs) == T_STRING)
	    attrs = rb_ary_to_ary (attrs);
	  else
	    Check_Type (attrs, T_ARRAY);

	  if (RARRAY (attrs)->len == 0)
	    {
	      cattrs = NULL;
	    }
	  else
	    {
	      cattrs = ALLOCA_N (char *, (RARRAY (attrs)->len + 1));
	      for (i = 0; i < RARRAY (attrs)->len; i++)
		{
		  cattrs[i] = StringValueCStr (RARRAY (attrs)->ptr[i]);
		};
	      cattrs[RARRAY (attrs)->len] = NULL;
	    }
	}
    case 3:
      cbase = StringValueCStr (base);
      cscope = NUM2INT (scope);
      cfilter = StringValueCStr (filter);
      break;
    default:
      rb_bug ("rb_ldap_conn_search_s");
    };

  (*cmsg) = NULL;
  if (tv.tv_sec == 0 && tv.tv_usec == 0)
    {
      (*ldapdata)->err = ldap_search_s (cldap, cbase, cscope, cfilter,
					cattrs, cattrsonly, cmsg);
    }
  else
    {
      (*ldapdata)->err = ldap_search_st (cldap, cbase, cscope, cfilter,
					 cattrs, cattrsonly, &tv, cmsg);
    }
  if (!(cmsg && (*cmsg)))
    {
      rb_raise (rb_eRuntimeError, "no result returned by search");
    }
  Check_LDAP_Result ((*ldapdata)->err);

#ifdef HAVE_LDAP_SORT_ENTRIES
  if (rb_ldap_sort_obj != Qnil)
    {
      ldap_sort_entries ((*ldapdata)->ldap, cmsg,
			 sort_attr, rb_ldap_internal_strcmp);
    };
#endif
  rb_ldap_sort_obj = Qnil;

  return (*ldapdata)->err;
}

static VALUE
rb_ldap_conn_search_b (VALUE rdata)
{
  void **data = (void **) rdata;
  LDAP *cldap = (LDAP *) data[0];
  LDAPMessage *cmsg = (LDAPMessage *) data[1];
  LDAPMessage *e;
  VALUE m;

  for (e = ldap_first_entry (cldap, cmsg); e != NULL;
       e = ldap_next_entry (cldap, e))
    {
      m = rb_ldap_entry_new (cldap, e);
      rb_ensure (rb_yield, m, rb_ldap_conn_invalidate_entry, m);
    }
  return Qnil;
}

static VALUE
rb_ldap_conn_search2_b (VALUE rdata)
{
  void **data = (void *) rdata;
  LDAP *cldap = (LDAP *) data[0];
  LDAPMessage *cmsg = (LDAPMessage *) data[1];
  VALUE ary = (VALUE) data[2];
  LDAPMessage *e;
  VALUE m;
  VALUE hash;

  for (e = ldap_first_entry (cldap, cmsg); e != NULL;
       e = ldap_next_entry (cldap, e))
    {
      m = rb_ldap_entry_new (cldap, e);
      hash = rb_ldap_entry_to_hash (m);
      rb_ary_push (ary, hash);
      if (rb_block_given_p ())
	{
	  rb_ensure (rb_yield, hash, rb_ldap_conn_invalidate_entry, m);
	}
    }
  return Qnil;
}

static VALUE
rb_ldap_msgfree (VALUE data)
{
  LDAPMessage *cmsg = (LDAPMessage *) data;
  ldap_msgfree (cmsg);
  return Qnil;
}

VALUE
rb_ldap_parse_result (LDAP * cldap, LDAPMessage * cmsg)
{
  int rc, err, i;
  char **referrals;
  LDAPControl **serverctrls;
  VALUE refs, ctls, ary;

  refs = rb_ary_new ();
  ctls = rb_ary_new ();
  ary = rb_ary_new ();

  rc = ldap_parse_result (cldap, cmsg, &err, NULL, NULL,
			  &referrals, &serverctrls, 0);
  Check_LDAP_Result (rc);
  Check_LDAP_Result (err);

  if (referrals)
    {
      for (i = 0; referrals[i]; i++)
	{
	  rb_ary_push (refs, rb_str_new2 (referrals[i]));
	}
    }

  if (serverctrls)
    {
      for (i = 0; serverctrls[i]; i++)
	{
	  rb_ary_push (ctls, rb_ldap_control_new2 (serverctrls[i]));
	}
    }

  rb_ary_push (ary, refs);
  rb_ary_push (ary, ctls);

  return ary;
}

/*
 * call-seq:
 * conn.search(base_dn, scope, filter, attrs=nil, attrsonly=false,
 *             sec=0, usec=0, s_attr=nil, s_proc=nil) { |entry| }  => self
 *
 * Perform a search, with the base DN +base_dn+, a scope of +scope+ and a
 * search filter of +filter+.
 *
 * If +attrs+ is present, it should be an array of the attributes that the
 * search should return. By default, all attributes are returned, which is the
 * same as specifying an empty array or *nil*. Alternatively, +attrs+ may be a
 * single string, in which case it will be treated as a single element array.
 *
 * If +attrsonly+ is *true*, attributes will be returned, but not their values.
 *
 * If +sec+ and/or +usec+ are given, they define the time-out for the search in
 * seconds and microseconds, respectively.
 *
 * If +s_attr+ is given, it specifies the attribute on which to sort the
 * entries returned by the server. If +s_proc+ is given, it specifies a Proc
 * object that will be used to sort the entries returned by the server.
 *
 * Note that not all results may be returned by this method. If a
 * size limit has been set for the number of results to be returned and this
 * limit is exceeded, the results set will be truncated. You can check for
 * this by calling LDAP::Conn#err immediately after this method and comparing
 * the result to LDAP::LDAP_SIZELIMIT_EXCEEDED.
 */
VALUE
rb_ldap_conn_search_s (int argc, VALUE argv[], VALUE self)
{
  RB_LDAP_DATA *ldapdata;
  LDAPMessage *cmsg;
  LDAP *cldap;
  VALUE rc_ary = Qnil;

  rb_ldap_conn_search_i (argc, argv, self, &ldapdata, &cmsg);
  cldap = ldapdata->ldap;

  if (ldapdata->err == LDAP_SUCCESS
      || ldapdata->err == LDAP_SIZELIMIT_EXCEEDED)
    {
      void *pass_data[] = { (void *) cldap, (void *) cmsg };

      rc_ary = rb_ldap_parse_result (cldap, cmsg);
      rb_iv_set (self, "@referrals", rb_ary_shift (rc_ary));
      rb_iv_set (self, "@controls", rb_ary_shift (rc_ary));

      rb_ensure (rb_ldap_conn_search_b, (VALUE) pass_data,
		 rb_ldap_msgfree, (VALUE) cmsg);
    };

  return self;
}

/*
 * call-seq:
 * conn.search2(base_dn, scope, filter, attrs=nil, attrsonly=false,
 *		sec=0, usec=0, s_attr=nil, s_proc=nil)  => array
 * conn.search2(base_dn, scope, filter, attrs=nil, attrsonly=false,
 *		sec=0, usec=0, s_attr=nil, s_proc=nil) { |entry_as_hash| }  => self
 *
 * Perform a search, with the base DN +base_dn+, a scope of +scope+ and a
 * search filter of +filter+.
 *
 * If +attrs+ is present, it should be an array of the attributes that the
 * search should return. By default, all attributes are returned, which is the
 * same as specifying an empty array or *nil*. Alternatively, +attrs+ may be a
 * single string, in which case it will be treated as a single element array.
 *
 * If +attrsonly+ is *true*, attributes will be returned, but not their values.
 *
 * If +sec+ and/or +usec+ are given, they define the time-out for the search in
 * seconds and microseconds, respectively.
 *
 * If +s_attr+ is given, it specifies the attribute on which to sort the
 * entries returned by the server. If +s_proc+ is given, it specifies a Proc
 * object that will be used to sort the entries returned by the server.
 *
 * Note that not all results may be returned by this method. If a
 * size limit has been set for the number of results to be returned and this
 * limit is exceeded, the results set will be truncated. You can check for
 * this by calling LDAP::Conn#err immediately after this method and comparing
 * the result to LDAP::LDAP_SIZELIMIT_EXCEEDED.
 */
VALUE
rb_ldap_conn_search2_s (int argc, VALUE argv[], VALUE self)
{
  RB_LDAP_DATA *ldapdata;
  LDAPMessage *cmsg;
  LDAP *cldap;
  VALUE ary = Qnil;
  VALUE rc_ary = Qnil;

  rb_ldap_conn_search_i (argc, argv, self, &ldapdata, &cmsg);
  cldap = ldapdata->ldap;

  ary = rb_ary_new ();
  if (ldapdata->err == LDAP_SUCCESS
      || ldapdata->err == LDAP_SIZELIMIT_EXCEEDED)
    {
      void *pass_data[] = { (void *) cldap, (void *) cmsg, (void *) ary };

      rc_ary = rb_ldap_parse_result (cldap, cmsg);
      rb_iv_set (self, "@referrals", rb_ary_shift (rc_ary));
      rb_iv_set (self, "@controls", rb_ary_shift (rc_ary));

      rb_ensure (rb_ldap_conn_search2_b, (VALUE) pass_data,
		 rb_ldap_msgfree, (VALUE) cmsg);
    }

  if (rb_block_given_p ())
    {
      return self;
    }
  else
    {
      return ary;
    }
}

#if defined(HAVE_LDAPCONTROL) && defined(HAVE_LDAP_SEARCH_EXT_S)
static int
rb_ldap_conn_search_ext_i (int argc, VALUE argv[], VALUE self,
			   RB_LDAP_DATA ** ldapdata, LDAPMessage ** cmsg)
{
  VALUE base, scope, filter, attrs, attrsonly;
  VALUE serverctrls, clientctrls, sec, usec, limit, s_attr, s_proc;

  LDAP *cldap;
  char *cbase;
  int cscope;
  int climit;
  char *cfilter;
  char **cattrs;
  char *sort_attr;
  int cattrsonly;
  int i;
  struct timeval tv;
  LDAPControl **sctrls, **cctrls;

  GET_LDAP_DATA (self, (*ldapdata));
  cldap = (*ldapdata)->ldap;

  cattrs = NULL;
  cattrsonly = 0;
  cctrls = NULL;
  sctrls = NULL;
  tv.tv_sec = 0;
  tv.tv_usec = 0;
  sort_attr = NULL;
  rb_ldap_sort_obj = Qnil;
  climit = 0;

  switch (rb_scan_args (argc, argv, "39",
			&base, &scope, &filter, &attrs, &attrsonly,
			&serverctrls, &clientctrls, &sec, &usec, &limit,
			&s_attr, &s_proc))
    {
    case 12:
      rb_ldap_sort_obj = s_proc;	/* Ruby's GC never start in a C function */
    case 11:
      if (rb_ldap_sort_obj == Qnil)
	{
	  rb_ldap_sort_obj = Qtrue;
	}
      sort_attr = StringValueCStr (s_attr);
    case 10:
      climit = NUM2INT (limit);
    case 9:
      tv.tv_usec = NUM2INT (usec);
    case 8:
      tv.tv_sec = NUM2INT (sec);
    case 7:
      cctrls = rb_ldap_get_controls (clientctrls);
    case 6:
      sctrls = rb_ldap_get_controls (serverctrls);
    case 5:
      cattrsonly = (attrsonly == Qtrue) ? 1 : 0;
    case 4:
      if (TYPE (attrs) == T_NIL)
	{
	  cattrs = NULL;
	}
      else
	{
	  if (TYPE (attrs) == T_STRING)
	    attrs = rb_ary_to_ary (attrs);
	  else
	    Check_Type (attrs, T_ARRAY);

	  if (RARRAY (attrs)->len == 0)
	    {
	      cattrs = NULL;
	    }
	  else
	    {
	      cattrs = ALLOCA_N (char *, (RARRAY (attrs)->len + 1));
	      for (i = 0; i < RARRAY (attrs)->len; i++)
		{
		  cattrs[i] = StringValueCStr (RARRAY (attrs)->ptr[i]);
		};
	      cattrs[RARRAY (attrs)->len] = NULL;
	    }
	}
    case 3:
      cbase = StringValueCStr (base);
      cscope = NUM2INT (scope);
      cfilter = StringValueCStr (filter);
      break;
    default:
      rb_bug ("rb_ldap_conn_search_s");
    };

  (*cmsg) = NULL;
  if (tv.tv_sec == 0 && tv.tv_usec == 0)
    {
      (*ldapdata)->err = ldap_search_ext_s (cldap, cbase, cscope, cfilter,
					    cattrs, cattrsonly,
					    sctrls, cctrls,
					    NULL, climit, cmsg);
    }
  else
    {
      (*ldapdata)->err = ldap_search_ext_s (cldap, cbase, cscope, cfilter,
					    cattrs, cattrsonly,
					    sctrls, cctrls,
					    &tv, climit, cmsg);
    }
  Check_LDAP_Result ((*ldapdata)->err);

#ifdef HAVE_LDAP_SORT_ENTRIES
  if (rb_ldap_sort_obj != Qnil)
    {
      ldap_sort_entries ((*ldapdata)->ldap, cmsg,
			 sort_attr, rb_ldap_internal_strcmp);
    };
#endif
  rb_ldap_sort_obj = Qnil;

  return (*ldapdata)->err;
};

/*
 * call-seq:
 * conn.search_ext(base_dn, scope, filter, attrs=nil, attrsonly=false,
 *                 sctrls, cctrls, sec=0, usec=0, s_attr=nil, s_proc=nil)
 *                 { |entry| }  => self
 *
 * Perform a search, with the base DN +base_dn+, a scope of +scope+ and a
 * search filter of +filter+.
 *
 * If +attrs+ is present, it should be an array of the attributes that the
 * search should return. By default, all attributes are returned, which is the
 * same as specifying an empty array or *nil*. Alternatively, +attrs+ may be a
 * single string, in which case it will be treated as a single element array.
 *
 * If +attrsonly+ is *true*, attributes will be returned, but not their values.
 *
 * +sctrls+ is an array of server controls, whilst +cctrls+ is an array of
 * client controls.
 *
 * If +sec+ and/or +usec+ are given, they define the time-out for the search in
 * seconds and microseconds, respectively.
 *
 * If +s_attr+ is given, it specifies the attribute on which to sort the
 * entries returned by the server. If +s_proc+ is given, it specifies a Proc
 * object that will be used to sort the entries returned by the server.
 *
 * Note that not all results may be returned by this method. If a
 * size limit has been set for the number of results to be returned and this
 * limit is exceeded, the results set will be truncated. You can check for
 * this by calling LDAP::Conn#err immediately after this method and comparing
 * the result to LDAP::LDAP_SIZELIMIT_EXCEEDED.
 */
VALUE
rb_ldap_conn_search_ext_s (int argc, VALUE argv[], VALUE self)
{
  RB_LDAP_DATA *ldapdata;
  LDAPMessage *cmsg;
  LDAP *cldap;

  rb_ldap_conn_search_ext_i (argc, argv, self, &ldapdata, &cmsg);
  cldap = ldapdata->ldap;

  if (ldapdata->err == LDAP_SUCCESS
      || ldapdata->err == LDAP_SIZELIMIT_EXCEEDED)
    {
      void *pass_data[] = { (void *) cldap, (void *) cmsg };
      rb_ensure (rb_ldap_conn_search_b, (VALUE) pass_data,
		 rb_ldap_msgfree, (VALUE) cmsg);
    };

  return self;
};

/*
 * call-seq:
 * conn.search_ext2(base_dn, scope, filter, attrs=nil,
 *                  attrsonly=false, sctrls, cctrls, sec=0, usec=0,
 *                  s_attr=nil, s_proc=nil)  => array
 * conn.search_ext2(base_dn, scope, filter, attrs=nil,
 *                  attrsonly=false, sctrls, cctrls, sec=0, usec=0,
 *                  s_attr=nil, s_proc=nil) { |entry_as_hash| }  => self
 *
 * Perform a search, with the base DN +base_dn+, a scope of +scope+ and a
 * search filter of +filter+.
 *
 * If +attrs+ is present, it should be an array of the attributes that the
 * search should return. By default, all attributes are returned, which is the
 * same as specifying an empty array or *nil*. Alternatively, +attrs+ may be a
 * single string, in which case it will be treated as a single element array.
 *
 * If +attrsonly+ is *true*, attributes will be returned, but not their values.
 *
 * +sctrls+ is an array of server controls, whilst +cctrls+ is an array of
 * client controls.
 *
 * If +sec+ and/or +usec+ are given, they define the time-out for the search in
 * seconds and microseconds, respectively.
 *
 * If +s_attr+ is given, it specifies the attribute on which to sort the
 * entries returned by the server. If +s_proc+ is given, it specifies a Proc
 * object that will be used to sort the entries returned by the server.
 *
 * Note that not all results may be returned by this method. If a
 * size limit has been set for the number of results to be returned and this
 * limit is exceeded, the results set will be truncated. You can check for
 * this by calling LDAP::Conn#err immediately after this method and comparing
 * the result to LDAP::LDAP_SIZELIMIT_EXCEEDED.
 */
VALUE
rb_ldap_conn_search_ext2_s (int argc, VALUE argv[], VALUE self)
{
  RB_LDAP_DATA *ldapdata;
  LDAPMessage *cmsg;
  LDAP *cldap;
  VALUE ary;

  rb_ldap_conn_search_ext_i (argc, argv, self, &ldapdata, &cmsg);
  cldap = ldapdata->ldap;

  ary = rb_ary_new ();
  if (ldapdata->err == LDAP_SUCCESS
      || ldapdata->err == LDAP_SIZELIMIT_EXCEEDED)
    {
      void *pass_data[] = { (void *) cldap, (void *) cmsg, (void *) ary };
      rb_ensure (rb_ldap_conn_search2_b, (VALUE) pass_data,
		 rb_ldap_msgfree, (VALUE) cmsg);
    }

  if (rb_block_given_p ())
    {
      return self;
    }
  else
    {
      return ary;
    }
}
#endif

/*
 * call-seq:
 * conn.add(dn, attrs)  => self
 *
 * Add an entry with the DN, +dn+, and the attributes, +attrs+. +attrs+
 * should be either an array of LDAP#Mod objects or a hash of attribute/value
 * array pairs.
 */
VALUE
rb_ldap_conn_add_s (VALUE self, VALUE dn, VALUE attrs)
{
  RB_LDAP_DATA *ldapdata;
  char *c_dn;
  LDAPMod **c_attrs;
  int i;

  switch (TYPE (attrs))
    {
    case T_HASH:
      attrs = rb_ldap_hash2mods (rb_mLDAP,
				 INT2NUM (LDAP_MOD_ADD | LDAP_MOD_BVALUES),
				 attrs);
      break;
    case T_ARRAY:
      break;
    default:
      rb_raise (rb_eTypeError, "must be a hash or an array");
    };

  GET_LDAP_DATA (self, ldapdata);
  c_dn = StringValueCStr (dn);
  c_attrs = ALLOCA_N (LDAPMod *, (RARRAY (attrs)->len + 1));

  for (i = 0; i < RARRAY (attrs)->len; i++)
    {
      VALUE mod = RARRAY (attrs)->ptr[i];
      RB_LDAPMOD_DATA *moddata;
      Check_Kind (mod, rb_cLDAP_Mod);
      GET_LDAPMOD_DATA (mod, moddata);
      c_attrs[i] = moddata->mod;
    };
  c_attrs[i] = NULL;

  ldapdata->err = ldap_add_s (ldapdata->ldap, c_dn, c_attrs);
  Check_LDAP_Result (ldapdata->err);

  return self;
};

#if defined(HAVE_LDAPCONTROL) && defined(HAVE_LDAP_ADD_EXT_S)
/*
 * call-seq:
 * conn.add_ext(dn, attrs, sctrls, cctrls)  => self
 *
 * Add an entry with the DN, +dn+, and the attributes, +attrs+. +attrs+
 * should be either an array of LDAP#Mod objects or a hash of attribute/value
 * array pairs. +sctrls+ is an array of server controls, whilst +cctrls+ is
 * an array of client controls.
 */
VALUE
rb_ldap_conn_add_ext_s (VALUE self, VALUE dn, VALUE attrs,
			VALUE serverctrls, VALUE clientctrls)
{
  RB_LDAP_DATA *ldapdata;
  char *c_dn;
  LDAPMod **c_attrs;
  int i;
  LDAPControl **sctrls, **cctrls;

  switch (TYPE (attrs))
    {
    case T_HASH:
      attrs = rb_ldap_hash2mods (rb_mLDAP,
				 INT2NUM (LDAP_MOD_ADD | LDAP_MOD_BVALUES),
				 attrs);
      break;
    case T_ARRAY:
      break;
    default:
      rb_raise (rb_eTypeError, "must be a hash or an array");
    };

  GET_LDAP_DATA (self, ldapdata);
  c_dn = StringValueCStr (dn);
  c_attrs = ALLOCA_N (LDAPMod *, (RARRAY (attrs)->len + 1));
  sctrls = rb_ldap_get_controls (serverctrls);
  cctrls = rb_ldap_get_controls (clientctrls);

  for (i = 0; i < RARRAY (attrs)->len; i++)
    {
      VALUE mod = RARRAY (attrs)->ptr[i];
      RB_LDAPMOD_DATA *moddata;
      Check_Kind (mod, rb_cLDAP_Mod);
      GET_LDAPMOD_DATA (mod, moddata);
      c_attrs[i] = moddata->mod;
    };
  c_attrs[i] = NULL;

  ldapdata->err =
    ldap_add_ext_s (ldapdata->ldap, c_dn, c_attrs, sctrls, cctrls);
  Check_LDAP_Result (ldapdata->err);

  return self;
}
#endif

/*
 * call-seq:
 * conn.modify(dn, mods)  => self
 *
 * Modify an entry with the DN, +dn+, and the attributes, +mods+. +mods+
 * should be either an array of LDAP#Mod objects or a hash of attribute/value
 * array pairs.
 */
VALUE
rb_ldap_conn_modify_s (VALUE self, VALUE dn, VALUE attrs)
{
  RB_LDAP_DATA *ldapdata;
  char *c_dn;
  LDAPMod **c_attrs;
  int i;

  switch (TYPE (attrs))
    {
    case T_HASH:
      attrs =
	rb_ldap_hash2mods (rb_mLDAP,
			   INT2NUM (LDAP_MOD_REPLACE | LDAP_MOD_BVALUES),
			   attrs);
      break;
    case T_ARRAY:
      break;
    default:
      rb_raise (rb_eTypeError, "must be a hash or an array");
    };

  GET_LDAP_DATA (self, ldapdata);
  c_dn = StringValueCStr (dn);
  c_attrs = ALLOC_N (LDAPMod *, RARRAY (attrs)->len + 1);

  for (i = 0; i < RARRAY (attrs)->len; i++)
    {
      VALUE mod = RARRAY (attrs)->ptr[i];
      RB_LDAPMOD_DATA *moddata;
      Check_Kind (mod, rb_cLDAP_Mod);
      GET_LDAPMOD_DATA (mod, moddata);
      c_attrs[i] = moddata->mod;
    };
  c_attrs[i] = NULL;

  ldapdata->err = ldap_modify_s (ldapdata->ldap, c_dn, c_attrs);
  Check_LDAP_Result (ldapdata->err);

  return self;
};

#if defined(HAVE_LDAPCONTROL) && defined(HAVE_LDAP_MODIFY_EXT_S)
/*
 * call-seq:
 * conn.modify_ext(dn, mods, sctrls, cctrls)  => self
 *
 * Modify an entry with the DN, +dn+, and the attributes, +mods+. +mods+
 * should be either an array of LDAP#Mod objects or a hash of attribute/value
 * array pairs. +sctrls+ is an array of server controls, whilst +cctrls+ is
 * an array of client controls.
 */
VALUE
rb_ldap_conn_modify_ext_s (VALUE self, VALUE dn, VALUE attrs,
			   VALUE serverctrls, VALUE clientctrls)
{
  RB_LDAP_DATA *ldapdata;
  char *c_dn;
  LDAPMod **c_attrs;
  int i;
  LDAPControl **sctrls, **cctrls;

  switch (TYPE (attrs))
    {
    case T_HASH:
      attrs =
	rb_ldap_hash2mods (rb_mLDAP,
			   INT2NUM (LDAP_MOD_REPLACE | LDAP_MOD_BVALUES),
			   attrs);
      break;
    case T_ARRAY:
      break;
    default:
      rb_raise (rb_eTypeError, "must be a hash or an array");
    };

  GET_LDAP_DATA (self, ldapdata);
  c_dn = StringValueCStr (dn);
  c_attrs = ALLOC_N (LDAPMod *, RARRAY (attrs)->len + 1);
  sctrls = rb_ldap_get_controls (serverctrls);
  cctrls = rb_ldap_get_controls (clientctrls);

  for (i = 0; i < RARRAY (attrs)->len; i++)
    {
      VALUE mod = RARRAY (attrs)->ptr[i];
      RB_LDAPMOD_DATA *moddata;
      Check_Kind (mod, rb_cLDAP_Mod);
      GET_LDAPMOD_DATA (mod, moddata);
      c_attrs[i] = moddata->mod;
    };
  c_attrs[i] = NULL;

  ldapdata->err =
    ldap_modify_ext_s (ldapdata->ldap, c_dn, c_attrs, sctrls, cctrls);
  Check_LDAP_Result (ldapdata->err);

  return self;
}
#endif

/*
 * call-seq:
 * conn.modrdn(dn, new_rdn, delete_old_rdn)  => self
 *
 * Modify the RDN of the entry with DN, +dn+, giving it the new RDN,
 * +new_rdn+. If +delete_old_rdn+ is *true*, the old RDN value will be deleted
 * from the entry.
 */
VALUE
rb_ldap_conn_modrdn_s (VALUE self, VALUE dn, VALUE newrdn, VALUE delete_p)
{
  RB_LDAP_DATA *ldapdata;
  char *c_dn;
  char *c_newrdn;
  int c_delete_p;

  GET_LDAP_DATA (self, ldapdata);
  c_dn = StringValueCStr (dn);
  c_newrdn = StringValueCStr (newrdn);
  c_delete_p = (delete_p == Qtrue) ? 1 : 0;

  ldapdata->err = ldap_modrdn2_s (ldapdata->ldap, c_dn, c_newrdn, c_delete_p);
  Check_LDAP_Result (ldapdata->err);

  return self;
};

/*
 * call-seq:
 * conn.delete(dn)  => self
 *
 * Delete the entry with the DN, +dn+.
 */
VALUE
rb_ldap_conn_delete_s (VALUE self, VALUE dn)
{
  RB_LDAP_DATA *ldapdata;
  char *c_dn;

  GET_LDAP_DATA (self, ldapdata);
  c_dn = StringValueCStr (dn);

  ldapdata->err = ldap_delete_s (ldapdata->ldap, c_dn);
  Check_LDAP_Result (ldapdata->err);

  return self;
};

#if defined(HAVE_LDAPCONTROL) && defined(HAVE_LDAP_DELETE_EXT_S)
/*
 * call-seq:
 * conn.delete_ext(dn, sctrls, cctrls)  => self
 *
 * Delete the entry with the DN, +dn+. +sctrls+ is an array of server
 * controls, whilst +cctrls+ is an array of client controls.
 */
VALUE
rb_ldap_conn_delete_ext_s (VALUE self, VALUE dn,
			   VALUE serverctrls, VALUE clientctrls)
{
  RB_LDAP_DATA *ldapdata;
  char *c_dn;
  LDAPControl **sctrls, **cctrls;

  GET_LDAP_DATA (self, ldapdata);
  c_dn = StringValueCStr (dn);
  sctrls = rb_ldap_get_controls (serverctrls);
  cctrls = rb_ldap_get_controls (clientctrls);

  ldapdata->err = ldap_delete_ext_s (ldapdata->ldap, c_dn, sctrls, cctrls);
  Check_LDAP_Result (ldapdata->err);

  return self;
}
#endif

#if defined(HAVE_LDAP_COMPARE_S)
/*
 * call-seq:
 * conn.compare(dn, attr, val)  => true or false
 *
 * Compare the DN given as +dn+ to see whether it has the attribute +attr+
 * with a value of +val+.
 */
VALUE
rb_ldap_conn_compare_s (VALUE self, VALUE dn, VALUE attr, VALUE val)
{
  RB_LDAP_DATA *ldapdata;
  char *c_dn, *c_attr, *c_val;

  GET_LDAP_DATA (self, ldapdata);
  c_dn = StringValueCStr (dn);
  c_attr = StringValueCStr (attr);
  c_val = StringValueCStr (val);

  ldapdata->err = ldap_compare_s (ldapdata->ldap, c_dn, c_attr, c_val);

  if ((ldapdata->err) == LDAP_COMPARE_TRUE)
    return Qtrue;
  else if ((ldapdata->err) == LDAP_COMPARE_FALSE)
    return Qfalse;

  Check_LDAP_Result (ldapdata->err);

  fprintf (stderr, "rb_ldap_conn_compare_s() unexpectedly set no error.\n");

  return self;
}
#endif

#if defined(HAVE_LDAPCONTROL) && defined(HAVE_LDAP_COMPARE_EXT_S)
/*
 * call-seq:
 * conn.compare_ext(dn, attr, val, sctrls, cctrls)  => true or false
 *
 * Compare the DN given as +dn+ to see whether it has the attribute +attr+
 * with a value of +val+. +sctrls+ is an array of server controls, whilst
 * +cctrls+ is an array of client controls.
 */
VALUE
rb_ldap_conn_compare_ext_s (VALUE self, VALUE dn, VALUE attr, VALUE val,
			    VALUE serverctrls, VALUE clientctrls)
{
  RB_LDAP_DATA *ldapdata;
  char *c_dn, *c_attr;
#ifdef USE_WLDAP32
  char *c_val;
#endif
  struct berval bval;
  LDAPControl **sctrls, **cctrls;

  GET_LDAP_DATA (self, ldapdata);
  c_dn = StringValueCStr (dn);
  c_attr = StringValueCStr (attr);
#ifdef USE_WLDAP32
  c_val = StringValueCStr (val);
#endif
  bval.bv_val = StringValueCStr (val);
  bval.bv_len = RSTRING (val)->len;
  sctrls = rb_ldap_get_controls (serverctrls);
  cctrls = rb_ldap_get_controls (clientctrls);

  ldapdata->err = ldap_compare_ext_s (ldapdata->ldap, c_dn, c_attr,
#ifdef USE_WLDAP32
				      c_val,
#endif
				      &bval, sctrls, cctrls);

  if ((ldapdata->err) == LDAP_COMPARE_TRUE)
    return Qtrue;
  else if ((ldapdata->err) == LDAP_COMPARE_FALSE)
    return Qfalse;

  Check_LDAP_Result (ldapdata->err);

  fprintf (stderr,
	   "rb_ldap_conn_compare_ext_s() unexpectedly set no error.\n");

  return self;
}
#endif

/*
 * call-seq:
 * conn.err  => Fixnum
 *
 * Return the error associated with the most recent LDAP operation.
 */
VALUE
rb_ldap_conn_err (VALUE self)
{
  RB_LDAP_DATA *ldapdata;

  GET_LDAP_DATA (self, ldapdata);
  return INT2NUM (ldapdata->err);
};

/* Document-class: LDAP::Conn 
 *
 * Create and manipulate unencrypted LDAP connections.
 */
void
Init_ldap_conn ()
{
  rb_ldap_sort_obj = Qnil;

  rb_cLDAP_Conn = rb_define_class_under (rb_mLDAP, "Conn", rb_cData);
  rb_define_attr (rb_cLDAP_Conn, "referrals", 1, 0);
  rb_define_attr (rb_cLDAP_Conn, "controls", 1, 0);
  rb_define_attr (rb_cLDAP_Conn, "sasl_quiet", 1, 1);
#if RUBY_VERSION_CODE < 170
  rb_define_singleton_method (rb_cLDAP_Conn, "new", rb_ldap_class_new, -1);
#endif
#if RUBY_VERSION_CODE >= 173
  rb_define_alloc_func (rb_cLDAP_Conn, rb_ldap_conn_s_allocate);
#else
  rb_define_singleton_method (rb_cLDAP_Conn, "allocate",
			      rb_ldap_conn_s_allocate, 0);
#endif
  rb_define_singleton_method (rb_cLDAP_Conn, "open", rb_ldap_conn_s_open, -1);
  rb_define_singleton_method (rb_cLDAP_Conn, "set_option",
			      rb_ldap_conn_s_set_option, 2);
  rb_define_singleton_method (rb_cLDAP_Conn, "get_option",
			      rb_ldap_conn_s_get_option, 1);
  rb_ldap_conn_define_method ("initialize", rb_ldap_conn_initialize, -1);
  rb_ldap_conn_define_method ("start_tls", rb_ldap_conn_start_tls_s, -1);
  rb_ldap_conn_define_method ("simple_bind", rb_ldap_conn_simple_bind_s, -1);
  rb_ldap_conn_define_method ("bind", rb_ldap_conn_bind_s, -1);
  rb_ldap_conn_define_method ("bound?", rb_ldap_conn_bound, 0);
  rb_ldap_conn_define_method ("unbind", rb_ldap_conn_unbind, 0);
  rb_ldap_conn_define_method ("set_option", rb_ldap_conn_set_option, 2);
  rb_ldap_conn_define_method ("get_option", rb_ldap_conn_get_option, 1);
  rb_ldap_conn_define_method ("search", rb_ldap_conn_search_s, -1);
  rb_ldap_conn_define_method ("search2", rb_ldap_conn_search2_s, -1);
  rb_ldap_conn_define_method ("add", rb_ldap_conn_add_s, 2);
  rb_ldap_conn_define_method ("modify", rb_ldap_conn_modify_s, 2);
  rb_ldap_conn_define_method ("modrdn", rb_ldap_conn_modrdn_s, 3);
  rb_ldap_conn_define_method ("delete", rb_ldap_conn_delete_s, 1);
#if defined(HAVE_LDAP_COMPARE_S)
  rb_ldap_conn_define_method ("compare", rb_ldap_conn_compare_s, 3);
#endif
  rb_ldap_conn_define_method ("perror", rb_ldap_conn_perror, 1);
  rb_ldap_conn_define_method ("err2string", rb_ldap_conn_err2string, 1);
  rb_ldap_conn_define_method ("result2error", rb_ldap_conn_result2error, 1);
  rb_ldap_conn_define_method ("err", rb_ldap_conn_err, 0);

#if defined(HAVE_LDAP_SEARCH_EXT_S)
  rb_ldap_conn_define_method ("search_ext", rb_ldap_conn_search_ext_s, -1);
  rb_ldap_conn_define_method ("search_ext2", rb_ldap_conn_search_ext2_s, -1);
#endif
#if defined(HAVE_LDAP_ADD_EXT_S)
  rb_ldap_conn_define_method ("add_ext", rb_ldap_conn_add_ext_s, 4);
#endif
#if defined(HAVE_LDAP_MODIFY_EXT_S)
  rb_ldap_conn_define_method ("modify_ext", rb_ldap_conn_modify_ext_s, 4);
#endif
#if defined(HAVE_LDAP_DELETE_EXT_S)
  rb_ldap_conn_define_method ("delete_ext", rb_ldap_conn_delete_ext_s, 3);
#endif
#if defined(HAVE_LDAP_COMPARE_EXT_S)
  rb_ldap_conn_define_method ("compare_ext", rb_ldap_conn_compare_ext_s, 5);
#endif
};
