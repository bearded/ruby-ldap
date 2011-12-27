/*
 * clientauth.c
 * Composed by Yuri Arabadji @ Fused Network
 *
 * bugs only: yuri[.@.]deepunix.net
 */

#include "ruby.h"
#include "rbldap.h"
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdarg.h>
#include <errno.h>

#ifdef USE_SSL_CLIENTAUTH
#warning ########################################################
#warning
#warning "        Enabling highly experimental code.            "
#warning "Expect breakage, ice melting, floods and world terror."
#warning
#warning ########################################################

#include <nspr/nspr.h>
#include <ldap_ssl.h>
#include <ldappr.h>
#include <signal.h>

// helpful macros
#define LDAPTOOL_RESULT_IS_AN_ERROR( rc ) \
                ( (rc) != LDAP_SUCCESS && (rc) != LDAP_COMPARE_TRUE \
                && (rc) != LDAP_COMPARE_FALSE )

/* copied from ldaprot.h - required to parse the pwpolicy ctrl */
#define LDAP_TAG_PWP_WARNING	0xA0L   /* context specific + constructed */
#define LDAP_TAG_PWP_SECSLEFT	0x80L   /* context specific + primitive */
#define LDAP_TAG_PWP_GRCLOGINS	0x81L   /* context specific + primitive + 1 */
#define LDAP_TAG_PWP_ERROR	0x81L   /* context specific + primitive + 1 */


// checks for *SSL* error
#define Check_LDAP_Error_MSG(retval, errmsg) { \
  if( (long)(retval) == LDAP_OPT_ERROR ){ \
    rb_raise(rb_eLDAP_ResultError, "%s. Lower layer reported: %s.", errmsg, ldapssl_err2string(PORT_GetError())); \
  } \
}

////////////////////////////////////////////////////////////////////////////////

VALUE rb_cLDAP_SSLAuthConn;

// forward declare 'em
VALUE rb_ldap_sslauthconn_initialize(int, VALUE[], VALUE);
void ldaptool_print_referrals(char**);
void print_to_stdout(char*, ...);
void handle_sigint(int, siginfo_t*, void*);

////////////////////////////////////////////////////////////////////////////////
//
//  Thank you, ldaptool / common.c!
//
////////////////////////////////////////////////////////////////////////////////

/*
 * Wait for a result, check for and display errors and referrals.
 * Also recognize and display "Unsolicited notification" messages.
 * Returns an LDAP error code.
 */
int
wait4result(LDAP *ld, int msgid, struct berval **servercredp, char *msg) {
    LDAPMessage *res;
    int rc, received_only_unsolicited = 1;

    while (received_only_unsolicited) {
        res = NULL;
        if ((rc = ldap_result(ld, msgid, 1, (struct timeval *) NULL, &res))
                == LDAP_OPT_ERROR) {
            return ldaptool_print_lderror(ld, msg);
        }

        /*
         * Special handling for unsolicited notifications:
         *    1. Parse and display contents.
         *    2. go back and wait for another (real) result.
         */
        if (rc == LDAP_RES_EXTENDED
                && ldap_msgid(res) == LDAP_RES_UNSOLICITED) {
            rc = ldaptool_print_extended_response(ld, res,
                    "Unsolicited response");
        } else {
            rc = parse_result(ld, res, servercredp, msg, 1);
            received_only_unsolicited = 0; /* we're done */
        }
    }

    return ( rc);
}

/*
 * print contents of an extended response to stderr
 * this is mainly to support unsolicited notifications
 * Returns an LDAP error code (from the extended result).
 */
int
ldaptool_print_extended_response( LDAP *ld, LDAPMessage *res, char *msg )
{
    char		*oid;
    struct berval	*data;

    if ( ldap_parse_extended_result( ld, res, &oid, &data, 0 )
	    != LDAP_SUCCESS ) {
        ldaptool_print_lderror( ld, msg);
    } else {
	if ( oid != NULL ) {
	    if ( strcmp ( oid, LDAP_NOTICE_OF_DISCONNECTION ) == 0 ) {
                print_to_stdout("%s: Notice of Disconnection\n", msg);
	    } else {
                print_to_stdout("%s: OID %s\n", msg, oid);
	    }
	    ldap_memfree( oid );
	} else {
            print_to_stdout("%s: missing OID\n", msg);
	}

	if ( data != NULL ) {
            print_to_stdout("%s: Data (length %d):\n", msg, data->bv_len );
#if 0
/* XXXmcs: maybe we should display the actual data? */
	    lber_bprint( data->bv_val, data->bv_len );
#endif
	    ber_bvfree( data );
	}
    }

    return parse_result( ld, res, NULL, msg, 1 );
}


int
parse_result(LDAP *ld, LDAPMessage *res, struct berval **servercredp,
        char *msg, int freeit) {
    int rc, lderr, errno;
    char **refs = NULL;
    LDAPControl **ctrls;

    if ((rc = ldap_parse_result(ld, res, &lderr, NULL, NULL, &refs,
            &ctrls, 0)) != LDAP_SUCCESS) {
        (void) ldaptool_print_lderror(ld, msg);
        ldap_msgfree(res);
        return ( rc);
    }

    if ((rc = check_response_controls(ld, msg, ctrls, 1)) != LDAP_SUCCESS) {
        ldap_msgfree(res);
        return ( rc);
    }

    if (servercredp != NULL && (rc = ldap_parse_sasl_bind_result(ld, res,
            servercredp, 0)) != LDAP_SUCCESS) {
        (void) ldaptool_print_lderror(ld, msg);
        ldap_msgfree(res);
        return ( rc);
    }

    if (freeit) {
        ldap_msgfree(res);
    }

    if (LDAPTOOL_RESULT_IS_AN_ERROR(lderr)) {
        (void) ldaptool_print_lderror(ld, msg);
    }

    if (refs != NULL) {
        ldaptool_print_referrals(refs);
        ldap_value_free(refs);
    }

    return ( lderr);
}

/*
 * check for response controls. authentication response control
 * and PW POLICY control are the ones we care about right now.
 */
int
check_response_controls(LDAP *ld, char *msg, LDAPControl **ctrls, int freeit) {
    int i;
    int errno;
    int pw_days = 0, pw_hrs = 0, pw_mins = 0, pw_secs = 0; /* for pwpolicy */
    char *s = NULL;
    BerElement *ber = NULL;
    static const char *pwpolicy_err2str[] = {
        "Password has expired.",
        "Account is locked.",
        "Password has been reset by an administrator; you must change it.",
        "Password change not allowed.",
        "Must supply old password.",
        "Invalid password syntax.",
        "Password too short.",
        "Password too young.",
        "Password in history."
    };

    if (NULL != ctrls) {
        for (i = 0; NULL != ctrls[i]; ++i) {

            if (0 == strcmp(ctrls[i]->ldctl_oid,
                    LDAP_CONTROL_AUTH_RESPONSE)) {
                s = ctrls[i]->ldctl_value.bv_val;
                if (NULL == s) {
                    s = "Null";
                } else if (*s == '\0') {
                    s = "Anonymous";
                }
                print_to_stdout("%s: bound as %s\n", msg, s);
            } /* end of LDAP_CONTROL_AUTH_RESPONSE */

            if (0 == strcmp(ctrls[i]->ldctl_oid,
                    LDAP_CONTROL_PWEXPIRING)) {

                /* Warn the user his passwd is to expire */
                errno = 0;
                pw_secs = atoi(ctrls[i]->ldctl_value.bv_val);
                if (pw_secs > 0 && errno != ERANGE) {
                    if (pw_secs > 86400) {
                        pw_days = (pw_secs / 86400);
                        pw_secs = (pw_secs % 86400);
                    }
                    if (pw_secs > 3600) {
                        pw_hrs = (pw_secs / 3600);
                        pw_secs = (pw_secs % 3600);
                    }
                    if (pw_secs > 60) {
                        pw_mins = (pw_secs / 60);
                        pw_secs = (pw_secs % 60);
                    }

                    printf("%s: Warning ! Your password will expire after ", msg);
                    if (pw_days) {
                        printf("%d days, ", pw_days);
                    }
                    if (pw_hrs) {
                        printf("%d hrs, ", pw_hrs);
                    }
                    if (pw_mins) {
                        printf("%d mins, ", pw_mins);
                    }
                    printf("%d seconds.\n", pw_secs);
                }
            } /* end of LDAP_CONTROL_PWEXPIRING */

            if (0 == strcmp(ctrls[i]->ldctl_oid,
                    LDAP_X_CONTROL_PWPOLICY_RESPONSE)) {
                ber_tag_t tag1 = 0, tag2 = 0, tag3 = 0;
                ber_int_t warnvalue = 0;
                int grclogins = -1, secsleft = -1;
                ber_int_t errvalue = -1;
                static int err2str_size = sizeof (pwpolicy_err2str) / sizeof (pwpolicy_err2str[0]);

                if ((ber = ber_init(&(ctrls[i]->ldctl_value))) == NULL) {
                    fprintf(stderr, "%s: not enough memory\n", msg);
                    return ( LDAP_NO_MEMORY);
                }
                if (ber_scanf(ber, "{t", &tag1) == LBER_ERROR) {
                    /* error */
                    ber_free(ber, 1);
                    return (ldaptool_print_lderror(ld, msg));
                }
                switch (tag1) {
                    case LDAP_TAG_PWP_WARNING:
                        if (ber_scanf(ber, "{ti}", &tag2, &warnvalue)
                                == LBER_ERROR) {
                            /* error */
                            ber_free(ber, 1);
                            return (ldaptool_print_lderror(ld, msg));
                        }
                        switch (tag2) {
                            case LDAP_TAG_PWP_SECSLEFT:
                                secsleft = (int) warnvalue;
                                break;
                            case LDAP_TAG_PWP_GRCLOGINS:
                                grclogins = (int) warnvalue;
                                break;
                            default:
                                /* error */
                                ber_free(ber, 1);
                                return (ldaptool_print_lderror(ld, msg));
                        }
                        /* Now check for the error value if it's present */
                        if (ber_scanf(ber, "te", &tag3, &errvalue) != LBER_ERROR) {
                            if (tag3 != LDAP_TAG_PWP_ERROR) {
                                errvalue = -1;
                            }
                        }
                        break;
                    case LDAP_TAG_PWP_ERROR:
                        if (ber_scanf(ber, "e}", &errvalue)
                                == LBER_ERROR) {
                            /* error */
                            ber_free(ber, 1);
                            return (ldaptool_print_lderror(ld, msg));
                        }
                        break;
                    default: /* error */
                        ber_free(ber, 1);
                        return (ldaptool_print_lderror(ld, msg));
                }

                /* Now we have all the values */
                if (secsleft >= 0) {
                    fprintf(stderr, "%s: Password will expire in %d seconds\n",
                            msg, secsleft);
                }
                if (grclogins >= 0) {
                    fprintf(stderr, "%s: %d grace login(s) remain\n",
                            msg, grclogins);
                }
                if (errvalue >= 0 && errvalue < err2str_size) {
                    fprintf(stderr, "%s: %s\n",
                            msg, pwpolicy_err2str[errvalue]);
                } else if (errvalue != -1) {
                    fprintf(stderr, "%s: %s\n",
                            msg,
                            "Invalid error value in password policy response control");
                }
            } /* end of LDAP_X_CONTROL_PWPOLICY_RESPONSE */

        }

        if (freeit) {
            ldap_controls_free(ctrls);
            ber_free(ber, 1);
        }
    }
    return LDAP_SUCCESS;
}


/*
 * Like ldap_sasl_bind_s() but calls wait4result() to display
 * any referrals returned and report errors in a consistent way.
 */
int
ldaptool_sasl_bind_s(LDAP *ld, const char *dn, const char *mechanism,
        const struct berval *cred, LDAPControl **serverctrls,
        LDAPControl **clientctrls, struct berval **servercredp, char *msg) {
    int rc, msgid;

    if (servercredp != NULL) {
        *servercredp = NULL;
    }

    if ((rc = ldap_sasl_bind(ld, dn, mechanism, cred, serverctrls,
            clientctrls, &msgid)) == LDAP_SUCCESS) {
        rc = wait4result(ld, msgid, servercredp, msg);
    }

    return ( rc);
}

// Rebind in case we were unbound
VALUE
rb_ldap_sslauthconn_rebind(VALUE self)
{
  VALUE ary = rb_iv_get (self, "@args");

  return rb_ldap_sslauthconn_initialize(RARRAY_LEN(ary), RARRAY_PTR(ary), self);
}

////////////////////////////////////////////////////////////////////////////////
//
//  .bind
//
////////////////////////////////////////////////////////////////////////////////

/*
 * call-seq:
 * conn.bind(serverctrls = nil) {|conn| # optional block }
 *   => self
 *
 * Bind a LDAP connection with SASL EXTERNAL method,
 * with optional +serverctls+.
 * If a block is given, +self+ is yielded to the block.
 */
VALUE
rb_ldap_sslauthconn_s_bind(int argc, VALUE argv[], VALUE self) {
    RB_LDAP_DATA *ldapdata;

    VALUE arg1;

    LDAPControl **bindctrls = NULL;

    Data_Get_Struct(self, RB_LDAP_DATA, ldapdata);

    if (ldapdata->bind == 0) {
        if (rb_iv_get(self, "@args") != Qnil) {
            rb_ldap_sslauthconn_rebind(self);
            GET_LDAP_DATA(self, ldapdata);
        } else {
            rb_raise(rb_eLDAP_InvalidDataError,
                    "The LDAP handler has already unbound.");
        }
    } else {
        rb_raise(rb_eLDAP_Error, "already bound.");
    };

    switch (rb_scan_args(argc, argv, "01", &arg1)) {
        case 1:
            bindctrls = rb_ldap_get_controls(arg1);
        case 0:
            break;
        default:
            rb_bug("rb_ldap_sslauthconn_bind_s");
    }

    ldapdata->err = ldaptool_sasl_bind_s(ldapdata->ldap, NULL, LDAP_SASL_EXTERNAL, NULL,
            bindctrls, NULL, NULL, "clientauth_ldap_sasl_bind");

    Check_LDAP_Result(ldapdata->err);
    ldapdata->bind = 1;

    if (rb_block_given_p()) {
        rb_ensure(rb_yield, self, rb_ldap_conn_unbind, self);
        return Qnil;
    } else {
        return self;
    };
};

////////////////////////////////////////////////////////////////////////////////
//
//  .new
//
////////////////////////////////////////////////////////////////////////////////
VALUE
rb_ldap_sslauthconn_initialize(int argc, VALUE argv[], VALUE self)
{
    RB_LDAP_DATA *ldapdata;
    LDAP *cldap;
    char *chost = NULL;
    char *certpath = NULL;
    char *certname = NULL;
    char *keypass = NULL;
    int cport = LDAP_PORT;
    int ctls = 0;

    VALUE host, port, tls, cp, cn, key_pw, sctrls, cctrls;

    Data_Get_Struct(self, RB_LDAP_DATA, ldapdata);
    if (ldapdata->ldap)
        return Qnil;

    int anum = rb_scan_args(argc, argv, "62", &host, &port, &tls, &cp, &cn, &key_pw, &sctrls, &cctrls);

    if (anum < 6) {
        rb_bug("rb_ldap_auth_conn_new");
    } else if (anum >= 6) {
        chost = StringValueCStr(host);
        cport = NUM2INT(port);
        ctls = (tls == Qtrue) ? 1 : 0;
        certpath = (cp == Qnil) ? NULL : StringValueCStr(cp);
        certname = (cn == Qnil) ? NULL : StringValueCStr(cn);
        keypass = (key_pw == Qnil) ? NULL : StringValueCStr(key_pw);
    }

    // Here we go
    Check_LDAP_Error_MSG(ldapssl_clientauth_init(certpath, NULL, (keypass == NULL) ? 0 : 1, NULL, NULL),
            "SSLAuthConn: Failed to initialize NSS certificate storeage. -- ldapssl_clientauth_init");

    // Make sure we can SIGINT
    struct sigaction act = {
        .sa_sigaction = handle_sigint,
        .sa_flags = SA_RESTART | SA_SIGINFO
    };

    if (sigaction(SIGINT, &act, NULL) < 0) {
        print_to_stdout("error setting sigint");
    };

    cldap = tls ? (LDAP*)prldap_init(chost, cport, 0) : ldapssl_init(chost, cport, 1);

    Check_LDAP_Error_MSG((long) cldap,
            "SSLAuthConn: Init failure");

    Check_LDAP_Error_MSG(ldapssl_enable_clientauth(cldap, "", keypass, certname),
            "SSLAuthConn: Couldn't enable client auth");

    if (tls) {
        Check_LDAP_Error_MSG(ldap_start_tls_s(cldap, NULL, NULL),
            "SSLAuthConn: TLS failure");
    }

    // protect key
    char* ptr_orig = StringValuePtr(key_pw);
    char* iptr = ptr_orig;
    while ((iptr - ptr_orig <= 16) && ((char)*iptr != '\0')) {
        *iptr++ = 'X';
    }

    // set ruby stuff
    ldapdata->ldap = cldap;
    rb_iv_set(self, "@args", rb_ary_new4(argc, argv));

    return Qnil;
}

////////////////////////////////////////////////////////////////////////////////
//
//  Fancy printing stuff goes here
//
////////////////////////////////////////////////////////////////////////////////

/*
 *  Print referrals to stdout
 */
void
ldaptool_print_referrals(char **refs) 
{
    int i;

    if (refs != NULL) {
        for (i = 0; refs[ i ] != NULL; ++i) {
            print_to_stdout("Referral: %s\n", refs[i]);
        }
    }
}

/*
 * Retrieve and print an LDAP error message.  Returns the LDAP error code.
 */
int
ldaptool_print_lderror( LDAP *ld, char *msg)
{
    int lderr = ldap_get_lderrno( ld, NULL, NULL );

    ldap_perror(ld, msg);

    int sslerr = PORT_GetError();

    rb_warn("%s SSL sublayer reported error: ", msg, ldapssl_err2string(sslerr));

    return(lderr);
}

void
print_to_stdout(char* format, ...) {
    static char buf[512] = "";
    va_list ap;
    
    va_start(ap, format);
    vsnprintf(buf, sizeof(buf) - 1, format, ap);
    rb_io_write(rb_stdout, rb_str_new2(buf));
    va_end(ap);
}

void handle_sigint(int sig, siginfo_t *siginfo, void *context) {
    print_to_stdout("Requested to terminate [%d].\n", sig);
    exit(0);
}

VALUE
rb_ldap_sslauthconn_s_open(int argc, VALUE argv[], VALUE klass)
{
    rb_notimplement();
}

/*
 * call-seq:
 * LDAP::SSLAuthConn.new(host='localhost', port=LDAP_PORT,
 *                   start_tls=false, cert_path, cert_nickname,
 *                   key_password, sctrls=nil, cctrls=nil)
 *
 *   => LDAP::SSLAuthConn
 *
 * Return a new LDAP::SSLConn connection to the server, +host+, on port +port+.
 * If +start_tls+ is *true*, START_TLS will be used to establish the
 * connection, automatically setting the LDAP protocol version to v3 if it is
 * not already set.
 *
 * +sctrls+ is an array of server controls, whilst +cctrls+ is an array of
 * client controls.
 *
 * Method accepts at least 6 parameters and an optional block.
 *
 */
void
Init_ldap_clientauth()
{
    rb_cLDAP_SSLAuthConn =
            rb_define_class_under(rb_mLDAP, "SSLAuthConn", rb_cLDAP_SSLConn);
    rb_define_singleton_method(rb_cLDAP_SSLAuthConn, "open",
            rb_ldap_sslauthconn_s_open, -1);
    rb_define_method(rb_cLDAP_SSLAuthConn, "initialize",
            rb_ldap_sslauthconn_initialize, -1);

    rb_define_method(rb_cLDAP_SSLAuthConn, "bind",
            rb_ldap_sslauthconn_s_bind, -1);

}

#endif
