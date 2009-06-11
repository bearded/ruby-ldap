/*
 * rbldap.h
 * $Id: rbldap.h,v 1.17 2006/08/09 11:23:04 ianmacd Exp $
 */

#ifndef RB_LDAP_H
#define RB_LDAP_H 1

#ifdef USE_WLDAP32
# ifdef HAVE_WINLBER_H
#   include "winlber.h"
# endif
# include "winldap.h"
#else
# include <lber.h>
# include <ldap.h>
#endif

#ifdef HAVE_LDAP_SSL_H
#include <ldap_ssl.h>
#endif

#ifndef LDAP_OPT_SUCCESS
# define LDAP_OPT_SUCCESS (0)
# define LDAP_OPT_ERROR   (-1)
#endif

#define RB_LDAP_MAJOR_VERSION 0
#define RB_LDAP_MINOR_VERSION 9
#define RB_LDAP_PATCH_VERSION 9
#define RB_LDAP_VERSION "0.9.9"

#define LDAP_GET_OPT_MAX_BUFFER_SIZE    (1024)	/* >= sizeof(LDAPAPIInfo) */

#define RB_LDAP_SET_STR(var,val) {\
   Check_Type(val, T_STRING); \
   var = ALLOC_N(char, RSTRING_LEN(val) + 1); \
   memcpy(var, RSTRING_PTR(val), RSTRING_LEN(val) + 1); \
}

#if defined(HAVE_LDAP_SEARCH_EXT_S)
# define HAVE_LDAPCONTROL
#endif

typedef struct rb_ldap_data
{
  LDAP *ldap;
  int bind;
  int err;
} RB_LDAP_DATA;

#define RLDAP_DATA_PTR(obj) ((RB_LDAP_DATA*)DATA_PTR(obj))

typedef struct rb_ldapentry_data
{
  LDAP *ldap;
  LDAPMessage *msg;
} RB_LDAPENTRY_DATA;

typedef struct rb_ldapmod_data
{
  LDAPMod *mod;
} RB_LDAPMOD_DATA;


#ifndef HAVE_LDAP_MEMFREE
# define ldap_memfree(ptr) free(ptr)
#endif

extern VALUE rb_mLDAP;

extern VALUE rb_sLDAP_APIInfo;
extern VALUE rb_cLDAP_Controls;

extern VALUE rb_cLDAP_Conn;
extern VALUE rb_cLDAP_SSLConn;
extern VALUE rb_cLDAP_Entry;
extern VALUE rb_cLDAP_Mod;
extern VALUE rb_eLDAP_Error;
extern VALUE rb_eLDAP_ResultError;
extern VALUE rb_eLDAP_InvalidDataError;
extern VALUE rb_eLDAP_InvalidEntryError;

#ifdef LDAP_OPT_API_INFO
VALUE rb_ldap_apiinfo_new (LDAPAPIInfo *);
LDAPAPIInfo *rb_ldap_get_apiinfo (VALUE);
#endif /* LDAP_OPT_API_INFO */

#ifdef HAVE_LDAPCONTROL
VALUE rb_ldap_control_new (LDAPControl *);
LDAPControl *rb_ldap_get_control (VALUE);
LDAPControl **rb_ldap_get_controls (VALUE);
void rb_ldap_free_controls (LDAPControl ** ctrls);
#endif

VALUE rb_ldap_class_new (int, VALUE[], VALUE);
VALUE rb_ldap_dummy_method (int, VALUE[], VALUE);
VALUE rb_ldap_err2string (VALUE, VALUE);
VALUE rb_ldap_dn2ufn (VALUE, VALUE);
VALUE rb_ldap_hash2mods (VALUE, VALUE, VALUE);
VALUE rb_ldap_entry2hash (VALUE, VALUE);

VALUE rb_ldap_conn_new (VALUE, LDAP *);
VALUE rb_ldap_conn_simple_bind_s (int, VALUE[], VALUE);
VALUE rb_ldap_conn_bind_s (int, VALUE[], VALUE);
VALUE rb_ldap_conn_start_tls_s (int, VALUE[], VALUE);
VALUE rb_ldap_conn_unbind (VALUE);
VALUE rb_ldap_conn_set_option (VALUE, VALUE, VALUE);
VALUE rb_ldap_conn_get_option (VALUE, VALUE);
VALUE rb_ldap_conn_perror (VALUE, VALUE);
VALUE rb_ldap_conn_result2error (VALUE, VALUE);
VALUE rb_ldap_conn_err2string (VALUE, VALUE);
VALUE rb_ldap_conn_search_s (int, VALUE[], VALUE);
VALUE rb_ldap_conn_search2_s (int, VALUE[], VALUE);
VALUE rb_ldap_conn_add_s (VALUE, VALUE, VALUE);
VALUE rb_ldap_conn_modify_s (VALUE, VALUE, VALUE);
VALUE rb_ldap_conn_modrdn_s (VALUE, VALUE, VALUE, VALUE);
VALUE rb_ldap_conn_delete_s (VALUE, VALUE);
VALUE rb_ldap_conn_err (VALUE);
VALUE rb_ldap_conn_set_sort (VALUE, VALUE, VALUE);
VALUE rb_ldap_conn_get_sort (VALUE);

VALUE rb_ldap_saslconn_bind (int, VALUE[], VALUE);

VALUE rb_ldap_entry_new (LDAP *, LDAPMessage *);
VALUE rb_ldap_entry_get_dn (VALUE self);
VALUE rb_ldap_entry_get_values (VALUE, VALUE);
VALUE rb_ldap_entry_get_attributes (VALUE);
VALUE rb_ldap_entry_to_hash (VALUE);

VALUE rb_ldap_mod_new (int, char *, char **);
VALUE rb_ldap_mod_new2 (int, char *, struct berval **);
VALUE rb_ldap_mod_op (VALUE);
VALUE rb_ldap_mod_type (VALUE);
VALUE rb_ldap_mod_vals (VALUE);

#define Check_Kind(obj,klass) {\
  if(!rb_obj_is_kind_of(obj,klass))\
    rb_raise(rb_eTypeError,"type mismatch");\
};

#define Check_LDAP_Result(err) { \
  if( err != LDAP_SUCCESS && err != LDAP_SIZELIMIT_EXCEEDED ){ \
    rb_raise(rb_eLDAP_ResultError, ldap_err2string(err)); \
  } \
}

#define Check_LDAP_OPT_Result(err) { \
  if( err != LDAP_OPT_SUCCESS ){ \
    rb_raise(rb_eLDAP_ResultError, ldap_err2string(err)); \
  } \
}

#define GET_LDAP_DATA(obj,ptr) {\
  Data_Get_Struct(obj, struct rb_ldap_data, ptr); \
  if( ! ptr->ldap ){ \
    rb_raise(rb_eLDAP_InvalidDataError, "The LDAP handler has already unbound.");\
  } \
}

#define Check_LDAPENTRY(obj) {\
  RB_LDAPENTRY_DATA *ptr; \
  Data_Get_Struct(obj, struct rb_ldapmsg_data, ptr); \
  if( ! ptr->msg ){ \
    rb_raise(rb_eLDAP_InvalidEntryError, "%s is not a valid entry", \
	     STR2CSTR(rb_inspect(obj))); \
  }; \
}

#define GET_LDAPENTRY_DATA(obj,ptr) { \
  Data_Get_Struct(obj, struct rb_ldapentry_data, ptr); \
  if( ! ptr->msg ){ \
    rb_raise(rb_eLDAP_InvalidEntryError, "%s is not a valid entry", \
	     STR2CSTR(rb_inspect(obj))); \
  }; \
}

#define GET_LDAPMOD_DATA(obj,ptr) {\
  Data_Get_Struct(obj, struct rb_ldapmod_data, ptr); \
  if( ! ptr->mod ) \
    rb_raise(rb_eLDAP_InvalidDataError, "The Mod data is not ready for use."); \
}

#define rb_ldap_define_class(cname,parent) \
        rb_define_class_under(rb_mLDAP,cname,parent)

#define rb_ldap_conn_define_method(method,cfunc,argc) \
        rb_define_method(rb_cLDAP_Conn,method,cfunc,argc)
#define rb_ldap_entry_define_method(method,cfunc,argc) \
        rb_define_method(rb_cLDAP_Entry,method,cfunc,argc)
#define rb_ldap_mod_define_method(method,cfunc,argc) \
        rb_define_method(rb_cLDAP_Mod,method,cfunc,argc)

#endif
