/*
 * mod.c
 * $Id: mod.c,v 1.14 2005/03/07 22:57:34 ianmacd Exp $
 */

#include "ruby.h"
#include "rbldap.h"

VALUE rb_cLDAP_Mod;


void
rb_ldap_mod_free (RB_LDAPMOD_DATA * data)
{
  if (data->mod)
    {
      struct berval **bvals;
      char **svals;
      int i;

      if (data->mod->mod_op & LDAP_MOD_BVALUES)
	{
	  bvals = data->mod->mod_vals.modv_bvals;
	  for (i = 0; bvals[i] != NULL; i++)
	    {
	      xfree (bvals[i]);
	    }
	  xfree (bvals);
	}
      else
	{
	  svals = data->mod->mod_vals.modv_strvals;
	  for (i = 0; svals[i] != NULL; i++)
	    {
	      xfree (svals[i]);
	    }
	  xfree (svals);
	}
      xfree (data->mod);
    }
}

static LDAPMod *
rb_ldap_new_mod (int mod_op, char *mod_type, char **modv_strvals)
{
  LDAPMod *mod;

  if (mod_op & LDAP_MOD_BVALUES)
    {
      rb_bug ("rb_ldap_mod_new: illegal mod_op");
    }

  mod = ALLOC_N (LDAPMod, 1);
  mod->mod_op = mod_op;
  mod->mod_type = mod_type;
  mod->mod_vals.modv_strvals = modv_strvals;

  return mod;
}

VALUE
rb_ldap_mod_new (int mod_op, char *mod_type, char **modv_strvals)
{
  VALUE obj;
  RB_LDAPMOD_DATA *moddata;

  obj = Data_Make_Struct (rb_cLDAP_Mod, RB_LDAPMOD_DATA,
			  0, rb_ldap_mod_free, moddata);
  moddata->mod = rb_ldap_new_mod (mod_op, mod_type, modv_strvals);

  return obj;
}

static LDAPMod *
rb_ldap_new_mod2 (int mod_op, char *mod_type, struct berval **modv_bvals)
{
  LDAPMod *mod;

  if (!(mod_op & LDAP_MOD_BVALUES))
    {
      rb_bug ("rb_ldap_mod_new: illegal mod_op");
    }

  mod = ALLOC_N (LDAPMod, 1);
  mod->mod_op = mod_op;
  mod->mod_type = mod_type;
  mod->mod_vals.modv_bvals = modv_bvals;

  return mod;
}

VALUE
rb_ldap_mod_new2 (int mod_op, char *mod_type, struct berval ** modv_bvals)
{
  VALUE obj;
  RB_LDAPMOD_DATA *moddata;

  obj = Data_Make_Struct (rb_cLDAP_Mod, RB_LDAPMOD_DATA,
			  0, rb_ldap_mod_free, moddata);
  moddata->mod = rb_ldap_new_mod2 (mod_op, mod_type, modv_bvals);

  return obj;
}

static VALUE
rb_ldap_mod_s_allocate (VALUE klass)
{
  RB_LDAPMOD_DATA *moddata;
  VALUE obj;

  obj =
    Data_Make_Struct (klass, RB_LDAPMOD_DATA, 0, rb_ldap_mod_free, moddata);
  moddata->mod = NULL;

  return obj;
}

/*
 * call-seq:
 * Mod.new(mod_type, attr, vals)  => LDAP::Mod
 *
 * Create a new LDAP::Mod object of type +mod_type+. This is most commonly
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
rb_ldap_mod_initialize (int argc, VALUE argv[], VALUE self)
{
  struct berval **bvals;
  char **strvals;
  int mod_op;
  char *mod_type;
  int i;
  VALUE op, type, vals;
  RB_LDAPMOD_DATA *moddata;

  rb_scan_args (argc, argv, "3", &op, &type, &vals);
  Data_Get_Struct (self, RB_LDAPMOD_DATA, moddata);
  if (moddata->mod)
    return Qnil;

  mod_op = NUM2INT (op);
  mod_type = StringValueCStr (type);
  Check_Type (vals, T_ARRAY);

  if (mod_op & LDAP_MOD_BVALUES)
    {
      bvals = ALLOC_N (struct berval *, RARRAY (vals)->len + 1);
      for (i = 0; i < RARRAY (vals)->len; i++)
	{
	  VALUE str;
	  struct berval *bval;
	  str = RARRAY (vals)->ptr[i];
	  Check_Type (str, T_STRING);
	  bval = ALLOC_N (struct berval, 1);
	  bval->bv_len = RSTRING (str)->len;
	  RB_LDAP_SET_STR (bval->bv_val, str);
	  bvals[i] = bval;
	}
      bvals[i] = NULL;
      moddata->mod = rb_ldap_new_mod2 (mod_op, mod_type, bvals);
    }
  else
    {
      strvals = ALLOC_N (char *, RARRAY (vals)->len + 1);
      for (i = 0; i < RARRAY (vals)->len; i++)
	{
	  VALUE str;
	  char *sval;
	  str = RARRAY (vals)->ptr[i];
	  RB_LDAP_SET_STR (sval, str);
	  strvals[i] = sval;
	}
      strvals[i] = NULL;
      moddata->mod = rb_ldap_new_mod (mod_op, mod_type, strvals);
    }

  return Qnil;
}

/*
 * call-seq:
 * mod.mod_op  => Fixnum
 *
 * Return the type of modification associated with the LDAP::Mod object.
 * Standard types are *LDAP_MOD_ADD*, *LDAP_MOD_REPLACE* and
 * *LDAP_MOD_DELETE*, although any of these may be logically OR'ed with
 * *LDAP_MOD_BVALUES* to indicate that the values of the Mod object contain
 * binary data.
 */
VALUE
rb_ldap_mod_op (VALUE self)
{
  RB_LDAPMOD_DATA *moddata;

  GET_LDAPMOD_DATA (self, moddata);
  return INT2NUM (moddata->mod->mod_op);
}

/*
 * call-seq:
 * mod.mod_type  => String
 *
 * Return the name of the attribute associated with the LDAP::Mod object.
 */
VALUE
rb_ldap_mod_type (VALUE self)
{
  RB_LDAPMOD_DATA *moddata;

  GET_LDAPMOD_DATA (self, moddata);
  return rb_tainted_str_new2 (moddata->mod->mod_type);
}

/*
 * call-seq:
 * mod.mod_vals  => Array of String
 *
 * Return the values associated with the Mod object.
 */
VALUE
rb_ldap_mod_vals (VALUE self)
{
  RB_LDAPMOD_DATA *moddata;
  struct berval **bvals;
  char **svals;
  int i;
  VALUE val;

  GET_LDAPMOD_DATA (self, moddata);

  if (moddata->mod->mod_op & LDAP_MOD_BVALUES)
    {
      bvals = moddata->mod->mod_vals.modv_bvals;
      val = rb_ary_new ();
      for (i = 0; bvals[i] != NULL; i++)
	{
	  VALUE str;
	  str = rb_tainted_str_new (bvals[i]->bv_val, bvals[i]->bv_len);
	  rb_ary_push (val, str);
	}
    }
  else
    {
      svals = moddata->mod->mod_vals.modv_strvals;
      val = rb_ary_new ();
      for (i = 0; svals[i] != NULL; i++)
	{
	  VALUE str;
	  str = rb_tainted_str_new2 (svals[i]);
	  rb_ary_push (val, str);
	}
    }

  return val;
}

/* call-seq:
 * mod.inspect  => String
 *
 * Produce a concise representation of the Mod object.
 */
VALUE
rb_ldap_mod_inspect (VALUE self)
{
  VALUE str;
  VALUE hash = rb_hash_new ();
  char *c;

  c = rb_obj_classname (self);
  str = rb_str_new (0, strlen (c) + 10 + 16 + 1);	/* 10:tags 16:addr 1:nul */
  sprintf (RSTRING (str)->ptr, "#<%s:0x%lx ", c, self);
  RSTRING (str)->len = strlen (RSTRING (str)->ptr);

  switch (FIX2INT (rb_ldap_mod_op (self)) & ~LDAP_MOD_BVALUES)
    {
    case LDAP_MOD_ADD:
      rb_str_cat2 (str, "LDAP_MOD_ADD");
      break;
    case LDAP_MOD_DELETE:
      rb_str_cat2 (str, "LDAP_MOD_DELETE");
      break;
    case LDAP_MOD_REPLACE:
      rb_str_cat2 (str, "LDAP_MOD_REPLACE");
      break;
#ifdef LDAP_MOD_INCREMENT
    case LDAP_MOD_INCREMENT:
      rb_str_cat2 (str, "LDAP_MOD_INCREMENT");
      break;
#endif
#ifdef LDAP_MOD_OP
    case LDAP_MOD_OP:
      rb_str_cat2 (str, "LDAP_MOD_OP");
      break;
#endif
    default:
      /* We shouldn't end up here. */
      rb_str_cat2 (str, "unknown");
      break;
    }
  if (FIX2INT (rb_ldap_mod_op (self)) & LDAP_MOD_BVALUES)
    rb_str_cat2 (str, "|LDAP_MOD_BVALUES");
  rb_str_cat2 (str, "\n");

  rb_hash_aset (hash, rb_ldap_mod_type (self), rb_ldap_mod_vals (self));
  rb_str_concat (str, rb_inspect (hash));
  rb_str_cat2 (str, ">");

  return str;
}

/* Document-class: LDAP::Mod
 *
 * Create and manipulate LDAP::Mod objects, which can then be passed to methods
 * in the LDAP::Conn class, such as Conn#add, Conn#add_ext, Conn#modify and
 * Conn#modify_ext.
 */
void
Init_ldap_mod ()
{
  rb_cLDAP_Mod = rb_define_class_under (rb_mLDAP, "Mod", rb_cObject);
#if RUBY_VERSION_CODE < 170
  rb_define_singleton_method (rb_cLDAP_Mod, "new", rb_ldap_class_new, -1);
#endif
#if RUBY_VERSION_CODE >= 173
  rb_define_alloc_func (rb_cLDAP_Mod, rb_ldap_mod_s_allocate);
#else
  rb_define_singleton_method (rb_cLDAP_Mod, "allocate",
			      rb_ldap_mod_s_allocate, 0);
#endif
  rb_ldap_mod_define_method ("initialize", rb_ldap_mod_initialize, -1);
  rb_ldap_mod_define_method ("mod_op", rb_ldap_mod_op, 0);
  rb_ldap_mod_define_method ("mod_type", rb_ldap_mod_type, 0);
  rb_ldap_mod_define_method ("mod_vals", rb_ldap_mod_vals, 0);
  rb_ldap_mod_define_method ("inspect", rb_ldap_mod_inspect, 0);

  /*
     rb_ldap_mod_define_method("mod_op=", rb_ldap_mod_set_op, 1);
     rb_ldap_mod_define_method("mod_type=", rb_ldap_mod_set_type, 1);
     rb_ldap_mod_define_method("mod_vals=", rb_ldap_mod_set_vals, 1);
   */
}
