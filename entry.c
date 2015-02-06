/*
 * entry.c
 * $Id: entry.c,v 1.13 2005/03/15 10:15:32 ianmacd Exp $
 */

#include "ruby.h"
#include "rbldap.h"

VALUE rb_cLDAP_Entry;

static void
rb_ldap_entry_mark(RB_LDAPENTRY_DATA *edata)
{
  rb_gc_mark(edata->dn);
  rb_gc_mark(edata->attr);
  /* 
   * edata->ldap and edata->msg are managed in a block given by each search
   * operation. ldap_msgfree should be called after ldap_search.
   * they are just for C language interfaces, don't touch these members
   * in ruby method implementation.
   */
}

/*
 * load libldap's value data structure into ruby array of string
 */
static VALUE
rb_ldap_entry_load_val(LDAP *ldap, LDAPMessage *msg, char *c_attr)
{
  struct berval **bv;
  VALUE vals;
  int nvals;
  int i;

  bv = ldap_get_values_len(ldap, msg, c_attr);
  if (bv == NULL)
    return Qnil;

  nvals = ldap_count_values_len(bv);
  vals = rb_ary_new2(nvals);
  for (i = 0; i < nvals; i++) {
    rb_ary_push(vals, rb_tainted_str_new(bv[i]->bv_val, bv[i]->bv_len));
  }
  ldap_value_free_len(bv);

  return vals;
}

/*
 * load libldap's attributes data structure into ruby hash
 */
static VALUE
rb_ldap_entry_load_attr(LDAP *ldap, LDAPMessage *msg)
{
  VALUE hash = rb_hash_new();
  BerElement *ber = NULL;
  char *c_attr;

  for (c_attr = ldap_first_attribute(ldap, msg, &ber);
    c_attr != NULL;
    c_attr = ldap_next_attribute(ldap, msg, ber)) {
    VALUE attr = rb_tainted_str_new2(c_attr);
    VALUE vals = rb_ldap_entry_load_val(ldap, msg, c_attr);

    rb_hash_aset(hash, attr, vals);
    ldap_memfree(c_attr);
  }

#if !defined(USE_OPENLDAP1)
  ber_free(ber, 0);
#endif

  return hash;
}

void
rb_ldap_entry_free (RB_LDAPENTRY_DATA * edata)
{
  xfree(edata);
  /* edata->msg is valid in a block given by each search operation */
  /* ldap_msgfree should be called after ldap_search */
}

VALUE
rb_ldap_entry_new (LDAP * ldap, LDAPMessage * msg)
{
  VALUE val;
  RB_LDAPENTRY_DATA *edata;
  char *c_dn;

  val = Data_Make_Struct (rb_cLDAP_Entry, RB_LDAPENTRY_DATA,
			  rb_ldap_entry_mark, rb_ldap_entry_free, edata);
  edata->ldap = ldap;
  edata->msg = msg;

  /* get dn */
  c_dn = ldap_get_dn(ldap, msg);
  if (c_dn) {
    edata->dn = rb_tainted_str_new2(c_dn);
    ldap_memfree(c_dn);
  }
  else {
    edata->dn = Qnil;
  }

  /* get attributes */
  edata->attr = rb_ldap_entry_load_attr(ldap, msg);
  return val;
}

/*
 * call-seq:
 * entry.get_dn  => String
 * entry.dn      => String
 */
VALUE
rb_ldap_entry_get_dn (VALUE self)
{
  RB_LDAPENTRY_DATA *edata;

  GET_LDAPENTRY_DATA (self, edata);

  return edata->dn;
}

/*
 * call-seq:
 * entry.get_values(attr)  => Array of String
 * entry.vals(attr)        => Array of String
 * entry[attr]             => Array of String
 *
 * Return an array of all the values belonging to the attribute, +attr+, of
 * the entry.
 */
VALUE
rb_ldap_entry_get_values (VALUE self, VALUE attr)
{
  RB_LDAPENTRY_DATA *edata;

  GET_LDAPENTRY_DATA (self, edata);

  return rb_hash_aref(edata->attr, attr);
}

/*
 * call-seq:
 * entry.get_attributes  => Array of String
 * entry.attrs           => Array of String
 *
 * Return an array of all the attributes belonging to the entry.
 */
VALUE
rb_ldap_entry_get_attributes (VALUE self)
{
  RB_LDAPENTRY_DATA *edata;
  VALUE attrs;

  GET_LDAPENTRY_DATA (self, edata);

  attrs = rb_funcall(edata->attr, rb_intern("keys"), 0);
  if (TYPE(attrs) != T_ARRAY) {
    return Qnil;
  }

  return attrs;
}

/*
 * call-seq:
 * entry.to_hash  => Hash
 *
 * Convert the entry to a hash.
 */
VALUE
rb_ldap_entry_to_hash (VALUE self)
{
  RB_LDAPENTRY_DATA *edata;
  VALUE hash, dn_ary;

  GET_LDAPENTRY_DATA (self, edata);
  hash = rb_hash_dup(edata->attr);
  dn_ary = rb_ary_new3(1, edata->dn);
  rb_hash_aset(hash, rb_tainted_str_new2("dn"), dn_ary);
  return hash;
}

/*
 * call-seq:
 * entry.inspect  => String
 *
 * Produce a concise representation of the entry.
 */
VALUE
rb_ldap_entry_inspect (VALUE self)
{
  VALUE str;
  const char *c;

  c = rb_obj_classname (self);
  str = rb_str_new (0, strlen (c) + 10 + 16 + 1);	/* 10:tags 16:addr 1:nul */
  sprintf (RSTRING_PTR (str), "#<%s:0x%lx\n", c, self);

#if RUBY_VERSION_CODE < 190
  RSTRING(str)->len = strlen (RSTRING_PTR (str));
#else
  rb_str_set_len(str, strlen (RSTRING_PTR (str)));
#endif

  rb_str_concat (str, rb_inspect (rb_ldap_entry_to_hash (self)));
  rb_str_cat2 (str, ">");

  return str;
}

/* Document-class: LDAP::Entry
 *
 * These methods can be used to probe the entries returned by LDAP searches.
 */
void
Init_ldap_entry ()
{
  rb_cLDAP_Entry = rb_define_class_under (rb_mLDAP, "Entry", rb_cObject);
  rb_define_const (rb_mLDAP, "Message", rb_cLDAP_Entry);	/* for compatibility */
  rb_undef_method (CLASS_OF (rb_cLDAP_Entry), "new");
  rb_undef_alloc_func (rb_cLDAP_Entry);
  rb_ldap_entry_define_method ("get_dn", rb_ldap_entry_get_dn, 0);
  rb_ldap_entry_define_method ("get_values", rb_ldap_entry_get_values, 1);
  rb_ldap_entry_define_method ("get_attributes",
			       rb_ldap_entry_get_attributes, 0);
  rb_alias (rb_cLDAP_Entry, rb_intern ("dn"), rb_intern ("get_dn"));
  rb_alias (rb_cLDAP_Entry, rb_intern ("vals"), rb_intern ("get_values"));
  rb_alias (rb_cLDAP_Entry, rb_intern ("[]"), rb_intern ("get_values"));
  rb_alias (rb_cLDAP_Entry, rb_intern ("attrs"),
	    rb_intern ("get_attributes"));
  rb_ldap_entry_define_method ("to_hash", rb_ldap_entry_to_hash, 0);
  rb_ldap_entry_define_method ("inspect", rb_ldap_entry_inspect, 0);
}
