/* -*- C -*-
 * $Id: misc.c,v 1.11 2006/07/03 22:54:52 ianmacd Exp $
 */

#include "ruby.h"
#include "rbldap.h"

VALUE rb_sLDAP_APIInfo;
VALUE rb_cLDAP_Control;

#ifdef LDAP_OPT_API_INFO
VALUE
rb_ldap_apiinfo_new (LDAPAPIInfo * info)
{
  VALUE info_version, api_version, protocol_version;
  VALUE extensions, vendor_name, vendor_version;
  int i;

  info_version = INT2NUM (info->ldapai_info_version);
  api_version = INT2NUM (info->ldapai_api_version);
  protocol_version = INT2NUM (info->ldapai_protocol_version);
  vendor_version = INT2NUM (info->ldapai_vendor_version);
  vendor_name = rb_tainted_str_new2 (info->ldapai_vendor_name);
  extensions = rb_ary_new ();

  for (i = 0; info->ldapai_extensions[i]; i++)
    {
      rb_ary_push (extensions,
		   rb_tainted_str_new2 (info->ldapai_extensions[i]));
    }

  return rb_struct_new (rb_sLDAP_APIInfo,
			info_version, api_version, protocol_version,
			extensions, vendor_name, vendor_version, 0);
}

LDAPAPIInfo *
rb_ldap_get_apiinfo (VALUE data)
{
  LDAPAPIInfo *info;
  VALUE r_extensions;
  int len, i;
  char **c_extensions;

  if (data == Qnil)
    return NULL;

  info = ALLOC_N (LDAPAPIInfo, 1);
  info->ldapai_info_version =
    FIX2INT (rb_struct_getmember (data, rb_intern ("info_version")));
  info->ldapai_api_version =
    FIX2INT (rb_struct_getmember (data, rb_intern ("api_version")));
  info->ldapai_protocol_version =
    FIX2INT (rb_struct_getmember (data, rb_intern ("protocol_version")));
  r_extensions = rb_struct_getmember (data, rb_intern ("extensions"));
  len = RARRAY_LEN (r_extensions);
  c_extensions = ALLOCA_N (char *, len);
  for (i = 0; i <= len - 1; i++)
    {
      VALUE str = RARRAY_PTR (r_extensions)[i];
      RB_LDAP_SET_STR (c_extensions[i], str);
    }
  info->ldapai_extensions = c_extensions;
  RB_LDAP_SET_STR (info->ldapai_vendor_name,
		   rb_struct_getmember (data, rb_intern ("vendor_name")));
  info->ldapai_vendor_version =
    FIX2INT (rb_struct_getmember (data, rb_intern ("vendor_version")));

  return info;
}
#endif /* LDAP_OPT_API_INFO */

#ifdef HAVE_LDAPCONTROL
static void
rb_ldap_control_free (LDAPControl * ctl)
{
  if (ctl)
    {
      if (ctl->ldctl_value.bv_val)
	xfree (ctl->ldctl_value.bv_val);
      if (ctl->ldctl_oid)
	xfree (ctl->ldctl_oid);
      xfree (ctl);
    }
}

VALUE
rb_ldap_control_new (LDAPControl * ctl)
{
  if (!ctl)
    return Qnil;
  else
    return Data_Wrap_Struct (rb_cLDAP_Control, 0, rb_ldap_control_free, ctl);
}

/* Identical to rb_ldap_control_new, but does not define a routine with which
   to free memory. This should be called only by rb_ldap_parse_result().
 */
VALUE
rb_ldap_control_new2 (LDAPControl * ctl)
{
  if (!ctl)
    return Qnil;
  else
    return Data_Wrap_Struct (rb_cLDAP_Control, 0, 0, ctl);
}

/* This is called by #initialize_copy and is using for duping/cloning. */
VALUE
rb_ldap_control_copy (VALUE copy, VALUE orig)
{
  LDAPControl *orig_ctl, *copy_ctl;

  Data_Get_Struct (orig, LDAPControl, orig_ctl);
  Data_Get_Struct (copy, LDAPControl, copy_ctl);
  memcpy (copy_ctl, orig_ctl, (size_t) sizeof (LDAPControl));

  return copy;
}

static VALUE
rb_ldap_control_s_allocate (VALUE klass)
{
  LDAPControl *ctl;

  ctl = ALLOC_N (LDAPControl, 1);
  ctl->ldctl_value.bv_val = NULL;
  ctl->ldctl_value.bv_len = 0;
  ctl->ldctl_oid = NULL;
  ctl->ldctl_iscritical = 0;
  return Data_Wrap_Struct (klass, 0, rb_ldap_control_free, ctl);
}

#if RUBY_VERSION_CODE < 170
static VALUE
rb_ldap_control_s_new (int argc, VALUE argv[], VALUE klass)
{
  VALUE obj;

  obj = rb_ldap_control_s_allocate (klass);
  rb_obj_call_init (obj, argc, argv);

  return obj;
}
#endif

static VALUE
rb_ldap_control_set_value (VALUE self, VALUE val)
{
  LDAPControl *ctl;

  Data_Get_Struct (self, LDAPControl, ctl);

  if (ctl->ldctl_value.bv_val)
    free (ctl->ldctl_value.bv_val);

  if (val == Qnil)
    {
      ctl->ldctl_value.bv_val = NULL;
      ctl->ldctl_value.bv_len = 0;
    }
  else
    {
      RB_LDAP_SET_STR (ctl->ldctl_value.bv_val, val);
      ctl->ldctl_value.bv_len = RSTRING_LEN (val);
    }

  return val;
}

static VALUE
rb_ldap_control_get_value (VALUE self)
{
  LDAPControl *ctl;
  VALUE val;

  Data_Get_Struct (self, LDAPControl, ctl);

  if (ctl->ldctl_value.bv_len == 0 || ctl->ldctl_value.bv_val == NULL)
    {
      val = Qnil;
    }
  else
    {
      val =
	rb_tainted_str_new (ctl->ldctl_value.bv_val, ctl->ldctl_value.bv_len);
    }

  return val;
}

/*
 * Document-method: value
 *
 * call-seq:
 * ctrl.value  => String or nil
 *
 * Return the value of the control.
 */

/* 
 * Document-method: value=
 *
 * call-seq:
 * ctrl.value=(val)  => val
 *
 * Set the value of the control.
 */
static VALUE
rb_ldap_control_value (int argc, VALUE argv[], VALUE self)
{
  VALUE val;

  if (rb_scan_args (argc, argv, "01", &val) == 1)
    val = rb_ldap_control_set_value (self, val);
  else
    val = rb_ldap_control_get_value (self);
  return val;
}

static VALUE
rb_ldap_control_set_oid (VALUE self, VALUE val)
{
  LDAPControl *ctl;

  Data_Get_Struct (self, LDAPControl, ctl);

  if (ctl->ldctl_oid)
    free (ctl->ldctl_oid);

  if (val == Qnil)
    {
      ctl->ldctl_oid = NULL;
    }
  else
    {
      RB_LDAP_SET_STR (ctl->ldctl_oid, val);
    }

  return val;
}

static VALUE
rb_ldap_control_get_oid (VALUE self)
{
  LDAPControl *ctl;
  VALUE val;

  Data_Get_Struct (self, LDAPControl, ctl);

  if (ctl->ldctl_oid == NULL)
    {
      val = Qnil;
    }
  else
    {
      val = rb_tainted_str_new2 (ctl->ldctl_oid);
    }

  return val;
}

/*
 * Document-method: oid
 *
 * call-seq:
 * ctrl.oid  => String or nil
 *
 * Return the OID of the control.
 */

/* 
 * Document-method: oid=
 *
 * call-seq:
 * ctrl.oid=(oid)  => oid
 *
 * Set the OID of the control.
 */
static VALUE
rb_ldap_control_oid (int argc, VALUE argv[], VALUE self)
{
  VALUE val;
  LDAPControl *ctl;

  Data_Get_Struct (self, LDAPControl, ctl);
  if (rb_scan_args (argc, argv, "01", &val) == 1)
    {
      val = rb_ldap_control_set_oid (self, val);
    }
  else
    {
      val = rb_ldap_control_get_oid (self);
    }
  return val;
}

static VALUE
rb_ldap_control_set_critical (VALUE self, VALUE val)
{
  LDAPControl *ctl;

  Data_Get_Struct (self, LDAPControl, ctl);
  ctl->ldctl_iscritical = (val == Qtrue) ? 1 : 0;
  return val;
}

static VALUE
rb_ldap_control_get_critical (VALUE self)
{
  LDAPControl *ctl;
  VALUE val;

  Data_Get_Struct (self, LDAPControl, ctl);
  val = ctl->ldctl_iscritical ? Qtrue : Qfalse;

  return val;
}

/*
 * Document-method: critical
 *
 * call-seq:
 * ctrl.critical    => true or false
 * ctrl.critical?   => true or false
 * ctrl.iscritical  => true or false
 *
 * Return the criticality of the control.
 */

/*
 * Document-method: critical=
 *
 * call-seq:
 * ctrl.critical=(val)    => val
 * ctrl.iscritical=(val)  => val
 *
 * Set the criticality of the control. +val+ should be *true* or *false*.
 */
static VALUE
rb_ldap_control_critical (int argc, VALUE argv[], VALUE self)
{
  VALUE val;
  LDAPControl *ctl;

  Data_Get_Struct (self, LDAPControl, ctl);
  if (rb_scan_args (argc, argv, "01", &val) == 1)
    {
      val = rb_ldap_control_set_critical (self, val);
    }
  else
    {
      val = rb_ldap_control_get_critical (self);
    }
  return val;
}

/*
 * Document-method: new
 *
 * call-seq:
 * LDAP::Control.new(oid, value, criticality)  => LDAP::Control
 *
 * Create a new LDAP::Control. +oid+ is the OID of the control, +value+ is the
 * value to be assigned to the control, and +criticality+ is the criticality
 * of the control, which should be *true* or *false*.
 */
static VALUE
rb_ldap_control_initialize (int argc, VALUE argv[], VALUE self)
{
  VALUE oid, value, critical;

  switch (rb_scan_args (argc, argv, "03", &oid, &value, &critical))
    {
    case 3:
      rb_ldap_control_set_critical (self, critical);
    case 2:
      rb_ldap_control_set_value (self, value);
    case 1:
      rb_ldap_control_set_oid (self, oid);
    default:
      break;
    }

  return Qnil;
}

/*
 * call-seq:
 * ctrl.inspect  => String
 *
 * Produce a concise representation of the control.
 */
static VALUE
rb_ldap_control_inspect (VALUE self)
{
  VALUE str;

  str = rb_tainted_str_new2 ("#<");
  rb_str_cat2 (str, rb_class2name (CLASS_OF (self)));
  rb_str_cat2 (str, " oid=");
  rb_str_concat (str, rb_inspect (rb_ldap_control_get_oid (self)));
  rb_str_cat2 (str, " value=");
  rb_str_concat (str, rb_inspect (rb_ldap_control_get_value (self)));
  rb_str_cat2 (str, " iscritical=");
  rb_str_concat (str, rb_inspect (rb_ldap_control_get_critical (self)));
  rb_str_cat2 (str, ">");

  return str;
}

VALUE
rb_ldap_controls_new (LDAPControl ** ctrls)
{
  int i;
  VALUE ary;

  if (!ctrls)
    return Qnil;

  ary = rb_ary_new ();
  for (i = 0; ctrls[i]; i++)
    rb_ary_push (ary, rb_ldap_control_new (ctrls[i]));

  return ary;
}

LDAPControl *
rb_ldap_get_control (VALUE obj)
{
  LDAPControl *ctl;

  if (obj == Qnil)
    {
      return NULL;
    }
  else
    {
      Data_Get_Struct (obj, LDAPControl, ctl);
      return ctl;
    }
}

LDAPControl **
rb_ldap_get_controls (VALUE data)
{
  LDAPControl **ctls;
  int len, i;

  if (data == Qnil)
    return NULL;

  Check_Type (data, T_ARRAY);
  len = RARRAY_LEN (data);
  ctls = ALLOC_N (LDAPControl *, len + 1);
  for (i = 0; i < len; i++)
    {
      ctls[i] = rb_ldap_get_control (rb_ary_entry (data, i));
    }
  ctls[len] = NULL;

  return ctls;
}
#endif

/* Document-class: LDAP::Control
 *
 * Create, manipulate and inspect LDAP controls.
 */
void
Init_ldap_misc ()
{
  rb_sLDAP_APIInfo = rb_struct_define ("APIInfo", "info_version",	/* ldapai_xxxx */
				       "api_version",
				       "protocol_version",
				       "extensions",
				       "vendor_name", "vendor_version", NULL);
  rb_define_const (rb_mLDAP, "APIInfo", rb_sLDAP_APIInfo);

#ifdef HAVE_LDAPCONTROL
  rb_cLDAP_Control = rb_define_class_under (rb_mLDAP, "Control", rb_cObject);
#if RUBY_VERSION_CODE < 170
  rb_define_singleton_method (rb_cLDAP_Control, "new",
                             rb_ldap_control_s_new, -1);
#endif
#if RUBY_VERSION_CODE >= 173
  rb_define_alloc_func (rb_cLDAP_Control, rb_ldap_control_s_allocate);
#else
  rb_define_singleton_method (rb_cLDAP_Control, "allocate",
                             rb_ldap_control_s_allocate, 0);
#endif
  rb_define_method (rb_cLDAP_Control, "initialize",
		    rb_ldap_control_initialize, -1);
  rb_define_method (rb_cLDAP_Control, "initialize_copy", rb_ldap_control_copy,
		    1);
  rb_define_method (rb_cLDAP_Control, "inspect", rb_ldap_control_inspect, 0);
  rb_define_method (rb_cLDAP_Control, "oid", rb_ldap_control_oid, -1);
  rb_define_method (rb_cLDAP_Control, "oid=", rb_ldap_control_oid, -1);
  rb_define_method (rb_cLDAP_Control, "value", rb_ldap_control_value, -1);
  rb_define_method (rb_cLDAP_Control, "value=", rb_ldap_control_value, -1);
  rb_define_method (rb_cLDAP_Control, "critical?", rb_ldap_control_critical,
		    -1);
  rb_define_method (rb_cLDAP_Control, "critical", rb_ldap_control_critical,
		    -1);
  rb_define_method (rb_cLDAP_Control, "critical=", rb_ldap_control_critical,
		    -1);
  rb_define_method (rb_cLDAP_Control, "iscritical", rb_ldap_control_critical,
		    -1);
  rb_define_method (rb_cLDAP_Control, "iscritical=", rb_ldap_control_critical,
		    -1);
#endif
}
