/*
 * $Id: winldap.h,v 1.6 2006/08/08 14:36:15 ianmacd Exp $
 *
 * Copyright (C) 2001 Takaaki Tateishi <ttate@kt.jaist.ac.jp>
 * Copyright (C) 2006 Ian Macdonald <ian@caliban.org>
 *
 */

#ifndef WINLDAP_H
#define WINLDAP_H

#include <windows.h>

#define LDAP_VERSION1 1
#define LDAP_VERSION2 2
#define LDAP_VERSION3 3

#define LDAP_VERSION_MIN LDAP_VERSION2
#define LDAP_VERSION     LDAP_VERSION2
#define LDAP_VERSION_MAX LDAP_VERSION3

/*
#define LDAP_API_VERSION
#define LDAP_APIINFO_VERSION 
*/
#define LDAP_VENDOR_NAME "Unknown"

#define LDAP_PORT 389
#define LDAP_SLL_PORT 636

#define LDAP_SCOPE_BASE       0x00
#define LDAP_SCOPE_ONELEVEL   0x01
#define LDAP_SCOPE_SUBTREE    0x02

#define LDAP_SUCCESS                       0x00
#define LDAP_OPERATIONS_ERROR              0x01
#define LDAP_PROTOCOL_ERROR                0x02
#define LDAP_TIMELIMIT_EXCEEDED            0x03
#define LDAP_SIZELIMIT_EXCEEDED            0x04
#define LDAP_COMPARE_FALSE                 0x05
#define LDAP_COMPARE_TRUE                  0x06
#define LDAP_AUTH_METHOD_NOT_SUPPORTED     0x07
#define LDAP_STRONG_AUTH_REQUIRED          0x08
#define LDAP_REFERRAL_V2                   0x09
#define LDAP_PARTIAL_RESULTS               0x09
#define LDAP_REFERRAL                      0x0a
#define LDAP_ADMIN_LIMIT_EXCEEDED          0x0b
#define LDAP_UNAVAILABLE_CRIT_EXTENSION    0x0c
#define LDAP_CONFIDENTIALITY_REQUIRED      0x0d

#define LDAP_NO_SUCH_ATTRIBUTE             0x10
#define LDAP_UNDEFINED_TYPE                0x11
#define LDAP_INAPPROPRIATE_MATCHING        0x12
#define LDAP_CONSTRAINT_VIOLATION          0x13
#define LDAP_ATTRIBUTE_OR_VALUE_EXISTS     0x14
#define LDAP_TYPE_OR_VALUE_EXISTS          0x14
#define LDAP_INVALID_SYNTAX                0x15

#define LDAP_NO_SUCH_OBJECT                0x20
#define LDAP_ALIAS_PROBLEM                 0x21
#define LDAP_INVALID_DN_SYNTAX             0x22
#define LDAP_IS_LEAF                       0x23
#define LDAP_ALIAS_DEREF_PROBLEM           0x24

#define LDAP_INAPPROPRIATE_AUTH            0x30
#define LDAP_INVALID_CREDENTIALS           0x31
#define LDAP_INSUFFICIENT_RIGHTS           0x32
#define LDAP_INSUFFICIENT_ACCESS           0x32
#define LDAP_BUSY                          0x33
#define LDAP_UNAVAILABLE                   0x34
#define LDAP_UNWILLING_TO_PERFORM          0x35
#define LDAP_LOOP_DETECT                   0x36

#define LDAP_NAMING_VIOLATION              0x40
#define LDAP_OBJECT_CLASS_VIOLATION        0x41
#define LDAP_NOT_ALLOWED_ON_NONLEAF        0x42
#define LDAP_NOT_ALLOWED_ON_RDN            0x43
#define LDAP_ALREADY_EXISTS                0x44
#define LDAP_NO_OBJECT_CLASS_MODS          0x45
#define LDAP_RESULTS_TOO_LARGE             0x46
#define LDAP_AFFECTS_MULTIPLE_DSAS         0x47

#define LDAP_OTHER                         0x50
#define LDAP_SERVER_DOWN                   0x51
#define LDAP_LOCAL_ERROR                   0x52
#define LDAP_ENCODING_ERROR                0x53
#define LDAP_DECODING_ERROR                0x54
#define LDAP_TIMEOUT                       0x55
#define LDAP_AUTH_UNKNOWN                  0x56
#define LDAP_FILTER_ERROR                  0x57
#define LDAP_USER_CANCELLED                0x58
#define LDAP_PARAM_ERROR                   0x59
#define LDAP_NO_MEMORY                     0x5a
#define LDAP_CONNECT_ERROR                 0x5b
#define LDAP_NOT_SUPPORTED                 0x5c
#define LDAP_CONTROL_NOT_FOUND             0x5d
#define LDAP_NO_RESULTS_RETURNED           0x5e
#define LDAP_MORE_RESULTS_TO_RETURN        0x5f
#define LDAP_CLIENT_LOOP                   0x60
#define LDAP_REFERRAL_LIMIT_EXCEEDED       0x61

#define LDAP_MOD_ADD                       0x00
#define LDAP_MOD_DELETE			   0x01
#define LDAP_MOD_REPLACE		   0x02
#define LDAP_MOD_BVALUES                   0x80

#define LDAP_AUTH_NONE                     0x00
#define LDAP_AUTH_SIMPLE                   0x80
#define LDAP_AUTH_SASL                     0x83
#define LDAP_AUTH_OTHERKIND                0x86

#define LDAP_AUTH_DPA                      0x2000  /* or LDAP_AUTH_OTHERKIND */
#define LDAP_AUTH_MSN                      0x0800  /* or LDAP_AUTH_OTHERKIND */
#define LDAP_AUTH_NEGOTIATE                0x0400  /* or LDAP_AUTH_OTHERKIND */
#define LDAP_AUTH_NTLM                     0x01000 /* or LDAP_AUTH_OTHERKIND */
#define LDAP_AUTH_SICILY                   0x0200  /* or LDAP_AUTH_OTHERKIND */
#define LDAP_AUTH_SSPI                     LDAP_AUTH_NEGOTIATE

#define LDAP_OPT_ON                        ((void*)1)
#define LDAP_OPT_OFF                       ((void*)0)

#define LDAP_OPT_API_INFO                  0x00
#define LDAP_OPT_DESC                      0x01
#define LDAP_OPT_DEREF                     0x02
#define LDAP_OPT_SIZELIMIT                 0x03
#define LDAP_OPT_TIMELIMIT                 0x04
#define LDAP_OPT_THREAD_FN_PTRS            0x05
#define LDAP_OPT_REBIND_FN                 0x06
#define LDAP_OPT_REBIND_ARG                0x07
#define LDAP_OPT_REFERRALS                 0x08
#define LDAP_OPT_RESTART                   0x09
#define LDAP_OPT_SSL                       0x0a
#define LDAP_OPT_IO_FN_PTRS                0x0b
#define LDAP_OPT_CACHE_FN_PTRS             0x0d
#define LDAP_OPT_CACHE_STRATEGY            0x0e
#define LDAP_OPT_CACHE_ENABLE              0x0f
#define LDAP_OPT_REFERRAL_HOP_LIMIT        0x10
#define LDAP_OPT_PROTOCOL_VERSION          0x11
#define LDAP_OPT_VERSION                   0x11
#define LDAP_OPT_API_FEATURE_INFO          0x15
#define LDAP_OPT_HOST_NAME                 0x30
#define LDAP_OPT_ERROR_NUMBER              0x31
#define LDAP_OPT_ERROR_STRING              0x32
#define LDAP_OPT_SERVER_ERROR              0x33
#define LDAP_OPT_SERVER_EXT_ERROR          0x34
#define LDAP_OPT_PING_KEEP_ALIVE           0x36
#define LDAP_OPT_PING_WAIT_TIME            0x37
#define LDAP_OPT_PING_LIMIT                0x38
#define LDAP_OPT_DNSDOMAIN_NAME            0x3b
#define LDAP_OPT_GETDSNAME_FLAGS           0x3d
#define LDAP_OPT_HOST_REACHABLE            0x3e
#define LDAP_OPT_PROMPT_CREDENTIALS        0x3f
#define LDAP_OPT_TCP_KEEPALIVE             0x40
#define LDAP_OPT_REFERRAL_CALLBACK         0x70
#define LDAP_OPT_CLIENT_CERTIFICATE        0x80
#define LDAP_OPT_SERVER_CERTIFICATE        0x81
#define LDAP_OPT_AUTO_RECONNECT            0x91
#define LDAP_OPT_SSPI_FLAGS                0x92
#define LDAP_OPT_SSL_INFO                  0x93
#define LDAP_OPT_REF_DEREF_CONN_PER_MSG    0x94
#define LDAP_OPT_SIGN                      0x95
#define LDAP_OPT_ENCRYPT                   0x95
#define LDAP_OPT_SASL_METHOD               0x97
#define LDAP_OPT_AREC_EXCLUSIVE            0x98
#define LDAP_OPT_SECURITY_CONTEXT          0x99
#define LDAP_OPT_ROOTDSE_CACHE             0x9a

#define LDAP_DEREF_SEARCHING               0x01
#define LDAP_DEREF_FINDING                 0x02
#define LDAP_DEREF_ALWAYS                  0x03

/*
The flags for LDAP_OPT_GETDSNAME_FLAGS:
DS_FORCE_REDISCOVERY
DS_DIRECTORY_SERVICE_REQUIRED
DS_DIRECTORY_SERVICE_PREFERRED
DS_GC_SERVER_REQUIRED DS_PDC_REQUIRED
DS_WRITABLE_REQUIRED
DS_FDC_REQUIRED
DS_IP_REQUIRED
DS_KDC_REQUIRED
DS_TIMESERV_REQUIRED
DS_IS_FLAT_NAME
DS_IS_DNS_NAME
*/


struct ldap;
typedef struct ldap LDAP, *PLDAP;

typedef struct ldapcontrol {
  PCHAR ldctl_oid;
  struct berval ldctl_value;
  BOOLEAN ldctl_iscritical;
} LDAPControl, *PLDAPControl;

struct ldapmsg;
typedef struct ldapmsg LDAPMessage, *PLDAPMessage;


typedef struct ldapmod {
  ULONG mod_op;
  PCHAR mod_type;
  union
  {
    PCHAR* modv_strvals;
    struct berval** modv_bvals;
  }mod_vals;
} LDAPMod, *PLDAPMod;

typedef struct ldapsortkey {
  PCHAR sk_attrtype;
  PCHAR sk_matchruleoid;
  BOOLEAN sk_reverseorder;
} LDAPSortKey, *PLDAPSortKey;

/*
typedef struct LdapReferralCallback {
  ULONG SizeOfCallbacks;
  QUERYFORCONNECTION* QueryForConnection;
  NOTIFYOFNEWCONNECTION* NotifyRoutine;
  DEREFERENCECONNECTION* DereferenceRoutine;
} LDAP_REFERRAL_CALLBACK, *PLDAP_REFERRAL_CALLBACK;
*/

struct ldapsearch;
typedef struct ldapsearch LDAPSearch, *PLDAPSearch;

#if defined(HAVE_SYS_TIME_H)
# include <sys/time.h>
#endif
typedef struct timeval LDAP_TIMEVAL;
typedef struct timeval *PLDAP_TIMEVAL;

typedef struct ldapvlvinfo {
  int ldvlv_version;
  unsigned long ldvlv_before_count;
  unsigned long ldvlv_after_count;
  unsigned long ldvlv_offset;
  unsigned long ldvlv_count;
  struct berval* ldvlv_attrvalue;
  struct berval* ldvlv_context;
  void* ldvlv_extradata;
} LDAPVLVInfo;

typedef struct ldap_apifeature_info {
  int ldapaif_info_version;
  char* ldapaif_name;
  int ldapaif_verion;
} LDAPAPIFeatureInfo;

typedef struct ldapapiinfo {
  int ldapai_info_version;
  int ldapai_api_version;
  int ldapai_protocol_version;
  char** ldapai_extensions;
  char* ldapai_vendor_name;
  int ldapai_vendor_version;
} LDAPAPIInfo;

ULONG ldap_abandon(LDAP *ld, ULONG msgid);
ULONG ldap_abandon_ext(LDAP *ld, ULONG msgid,
		       LDAPControl **sctls, LDAPControl **cctls);
LDAP* ldap_init(PCHAR host, ULONG port);
LDAP* ldap_sslinit(PCHAR host, ULONG port, int secure);
LDAP* ldap_open(PCHAR host, ULONG port);
ULONG ldap_bind_s(LDAP *ld, PCHAR who, PCHAR cred, ULONG authmethod);
ULONG ldap_unbind_s(LDAP *ld);
ULONG ldap_simple_bind_s(LDAP *ld, PCHAR dn, PCHAR passwd);
ULONG ldap_add_s(LDAP *ld, PCHAR dn, LDAPMod *attrs[]);
ULONG ldap_add_ext_s(LDAP *ld, PCHAR dn, LDAPMod *attrs[],
		     LDAPControl **sctls, LDAPControl **cctls);
ULONG ldap_compare_s(LDAP *ld, PCHAR dn, PCHAR attr, PCHAR value);
ULONG ldap_compare_ext_s(LDAP *ld, PCHAR dn, PCHAR attr, PCHAR value,
			 struct berval *data, LDAPControl **sctls,
			 LDAPControl **cctls);
ULONG ldap_count_entries(LDAP *ld, LDAPMessage *res);
ULONG ldap_count_values(PCHAR *vals);
ULONG ldap_delete_s(LDAP *ld,  PCHAR dn);
ULONG ldap_delete_ext_s(LDAP *ld, PCHAR dn,
			LDAPControl **sctls, LDAPControl **cctls);
ULONG ldap_modify_s(LDAP *ld, PCHAR dn, LDAPMod *mods[]);
ULONG ldap_modify_ext_s(LDAP *ld, PCHAR dn, LDAPMod *mods[],
			LDAPControl **sctls, LDAPControl **cctls);
ULONG ldap_modrdn_s(LDAP *ld, PCHAR olddn, PCHAR newdn);
ULONG ldap_modrdn2_s(LDAP *ld, PCHAR olddn, PCHAR newdn, int delold_flag);
ULONG ldap_search_s(LDAP *ld, PCHAR base, ULONG scope, PCHAR filter,
		    PCHAR attrs[], ULONG attrsonly, LDAPMessage **res);
ULONG ldap_search_ext_s(LDAP *ld, PCHAR base, ULONG scope, PCHAR filter,
			PCHAR attrs[], ULONG attrsonly,
			LDAPControl **sctls, LDAPControl **cctls,
			struct timeval *timeout, ULONG sizelimit,
			LDAPMessage **res);
ULONG ldap_search_st(LDAP *ld, PCHAR base, ULONG scope, PCHAR filter,
		     PCHAR attrs[], ULONG attrsonly,
		     struct timeval *timeout, LDAPMessage **res);

void ldap_perror(LDAP *ld, PCHAR msg);
PCHAR ldap_err2string(ULONG err);

ULONG ldap_msgfree(LDAPMessage *msg);
void ldap_memfree(PCHAR ptr);
void ldap_value_free(PCHAR *ptr);
void ldap_value_free_len(struct berval **vals);

PCHAR ldap_dn2ufn(PCHAR dn);
ULONG ldap_ufn2dn(PCHAR ufn, PCHAR *dn);

PCHAR ldap_first_attribute(LDAP *ld, LDAPMessage *entry, BerElement **ptr);
PCHAR ldap_next_attribute(LDAP *ld, LDAPMessage *entry, BerElement *ptr);

LDAPMessage *ldap_first_entry(LDAP *ld, LDAPMessage *res);
LDAPMessage *ldap_next_entry(LDAP *ld, LDAPMessage *entry);

PCHAR ldap_get_dn(LDAP *ld, LDAPMessage *entry);
PCHAR ldap_get_values(LDAP *ld, LDAPMessage *entry, PCHAR attr);
struct berval **ldap_get_values_len(LDAP *ld, LDAPMessage *msg, PCHAR attr);

ULONG ldap_get_option(LDAP *ld, int option, void *outval);
ULONG ldap_set_option(LDAP *ld, int option, void *inval);

ULONG ldap_connect(LDAP* ld, PLDAP_TIMEVAL *timeout);

#endif /* WINLDAP_H */
