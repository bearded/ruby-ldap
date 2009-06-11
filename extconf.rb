#!/usr/bin/env ruby-1.4
#
# extconf.rb for ldap extension
# $Id: extconf.rb,v 1.7 2006/04/18 23:49:56 ianmacd Exp $
#

require 'mkmf'

$INTERACTIVE = false

if( ARGV.include?("--help") )
  print <<EOF
  --with-ldap-dir    specify the LDAP directory.
  --with-ldap-include specify the directory containing ldap.h and lber.h.
  --with-ldap-lib    specify the directory containing the LDAP libraries.
  --with-netscape    build with Netscape SDK.
  --with-openldap1   build with OpenLDAP 1.x.
  --with-openldap2   build with OpenLDAP 2.x.
  --with-wldap32     Active Directory Client API.

The following are library configuration options:
  --with-libcrypto=crypto,   --without-libcrypto
  --with-libssl=ssl,         --without-libssl
  --with-libnsl=nsl,         --without-libnsl
  --with-libldap=ldap,       --without-libldap
  --with-liblber=lber,       --without-liblber
  --with-libldap_r=ldap_r,   --without-libldap_r
  --with-libpthread=pthread, --without-libpthread
  --with-libresolv=resolv,   --without-libresolv

  --help             show this help.
EOF
exit(0)
end

def find_files(dir = nil)
  if( dir )
    search_dirs = [dir]
  else
    search_dirs =
      ["/usr/local", "/usr", "/opt"] +
      Dir.glob("/usr/local/./*ldap*").collect{|d| d.gsub(/\/\.\//, "/")} +
      Dir.glob("/usr/./*ldap*").collect{|d| d.gsub(/\/\.\//, "/")}
  end
  for d in search_dirs
    h = File.join(d,"include","ldap.h")
    l = File.join(d,"lib","libldap*")
    if( File.exist?(h) )
      l = Dir.glob(l)[0]
      if( l )
	if( $INTERACTIVE )
	  print("--with-ldap-dir=#{d} [y/n]")
	  ans = $stdin.gets
	  ans.chop!
	  if( ans == "y" )
	    result = [d, File.basename(l).split(".")[0][3..-1], File.basename(h)]
	    return result
	    break
	  end
	else
	  print("--with-ldap-dir=#{d}\n")
	  result = [d, File.basename(l).split(".")[0][3..-1], File.basename(h)]
	  return result
	  break
	end
      end
    end
  end
end

def ldap_with_config(arg, default = nil)
  cfg1  = with_config(arg, nil)
  cfg2  = arg_config("--without-" + arg, nil)
  if( cfg1 )
    return cfg1
  else
    if( cfg2 )
      return nil
    else
      return default
    end
  end
end

$use_netscape  = ldap_with_config("netscape")
$use_openldap1 = ldap_with_config("openldap1")
$use_openldap2 = ldap_with_config("openldap2")
$use_wldap32   = ldap_with_config("wldap32")

dir_config('ldap')
$ldap_dir    = ldap_with_config("ldap-dir") || ldap_with_config("ldap")

$ldap_dir, $libldap, $ldap_h = find_files($ldap_dir)

if( !($use_netscape || $use_openldap1 || $use_openldap2 || $use_wldap32) )
  case $libldap
  when /^ldapssl[0-9]+$/
    print("--with-netscape\n")
    $use_netscape = "4"
  when /^ssldap50+$/, /^ldap50+$/
    print("--with-netscape=5")
    $use_netscape = "5"
  else
    print("--with-openldap2\n")
    $use_openldap2 = true
  end
end
if( $use_netscape == true )
  $use_netscape = "5"
end

if( $use_netscape )
  case $use_netscape
  when /^4/
    $defs << "-DUSE_NETSCAPE_SDK"
    #$libnsl     = ldap_with_config("libnsl", "nsl")
    #$libpthread = ldap_with_config("libpthread", "pthread")
    $libresolv  = ldap_with_config("libresolv", "resolv")
    $libldap    = ldap_with_config("libldap", $libldap)
    $libns      = ldap_with_config("libns", "nspr3,plc3,plds3").split(",")
  when /^5/
    $defs << "-DUSE_NETSCAPE_SDK"
    #$libnsl     = ldap_with_config("libnsl", "nsl")
    #$libpthread = ldap_with_config("libpthread", "pthread")
    $libresolv  = ldap_with_config("libresolv", "resolv")
    $libldap    = ldap_with_config("libldap", $libldap)
    $libns      = ldap_with_config("libns", "nspr4,plc4,plds4").split(",")
    $liblber    = ldap_with_config("liblber", "lber50")
    $libssl     = ldap_with_config("libssl", "ssl3")
  end
end

if( $use_openldap1 )
  $defs << "-DUSE_OPENLDAP1"
  $defs << "-DUSE_OPENLDAP"
  $libresolv  = ldap_with_config("libresolv", "resolv")
  $libldap   = ldap_with_config("libldap", "ldap")
  $liblber   = ldap_with_config("liblber", "lber")
end

if( $use_openldap2 )
  $defs << "-DUSE_OPENLDAP2"
  $defs << "-DUSE_OPENLDAP"
  # OpenLDAP 2.3 finally deprecates a bunch of non-_ext functions. We need
  # this to enable them.
  $defs << "-DLDAP_DEPRECATED"
  $libresolv  = ldap_with_config("libresolv", "resolv")
  $libcrypto  = ldap_with_config("libcrypto", "crypto")
  $libssl     = ldap_with_config("libssl", "ssl")
  $libpthread = ldap_with_config("libpthread", "pthread")
  $libnsl     = ldap_with_config("libnsl", "nsl")
  $liblber    = ldap_with_config("liblber", "lber")
  $libldap_r  = ldap_with_config("libldap_r", "ldap_r")
  $libldap    = ldap_with_config("libldap", "ldap")
end

if( $use_wldap32 )
  srcdir = File.dirname($0)
  if( !File.exist?("win") )
    Dir.mkdir("win")
  end
  `lib /def:#{srcdir}/win/wldap32.def /out:#{srcdir}/win/wldap32.lib`
  $defs << "-DUSE_WLDAP32"
  dir_config("wldap32", "#{srcdir}/win", "./win")
  $libldap = ldap_with_config("libldap", "wldap32")
end

if( $libpthread )
  $defs << "-D_REENTRANT"
end

if( $use_wldap32 )
  have_header("winldap.h")
  have_header("winlber.h")
  have_header("sys/time.h")
else
  ldap_h = have_header("ldap.h")
  lber_h = have_header("lber.h")
  ldap_ssl_h = have_header("ldap_ssl.h")
  if( !(ldap_h && lber_h) )
    print("can't find ldap.h and lber.h\n")
    print("use the option '--with-ldap-dir'!\n")
    exit(0)
  end

  have_header("openssl/ssl.h")    || have_header("ssl.h")
  have_header("openssl/crypto.h") || have_header("crypto.h")
end

for l in [$libcrypto, $libssl, $libnsl, $libpthread, $libresolv,
          $libns, $liblber, $libldap_r, $libldap].flatten
  if( l )
    have_library(l)
  end
end

have_func("ldap_init")
have_func("ldap_set_option")
have_func("ldap_get_option")
have_func("ldap_start_tls_s") if $use_openldap2
have_func("ldap_memfree")
have_func("ldap_perror") if !arg_config("--disable-ldap-perror")
have_func("ldap_sort_entries")
#have_func("ldap_sort_values")
have_func("ldapssl_init")  # NS SDK
have_func("ldap_sslinit")  # WLDAP32
have_func("ldap_sasl_bind_s")
have_func("ldap_compare_s")
have_func("ldap_add_ext_s")
have_func("ldap_compare_ext_s")
have_func("ldap_delete_ext_s")
have_func("ldap_modify_ext_s")
have_func("ldap_search_ext_s")
have_func("ldap_unbind_ext_s")
have_func("ldap_sasl_interactive_bind_s")

$defs << "-DRUBY_VERSION_CODE=#{RUBY_VERSION.gsub(/\D/, '')}"

create_makefile("ldap")


$slapd = ldap_with_config("slapd") || File.join($ldap_dir,"libexec","slapd")
$schema_dir = ldap_with_config("schema-dir")
if( !$schema_dir )
  $schema_dir = File.join($ldap_dir,"etc","openldap","schema")
  if( !File.exist?($schema_dir) )
    $schema_dir = File.join($ldap_dir,"etc","openldap")
  end
end

$run_test = "/bin/sh $(srcdir)/test/test.sh #{CONFIG['RUBY_INSTALL_NAME']}"
if( $use_openldap1 )
  $run_test += " openldap1"
else( $use_openldap2 )
  if( $libssl && $libcrypto )
    $run_test = "/bin/sh $(srcdir)/test/test.sh #{CONFIG['RUBY_INSTALL_NAME']} newcert; " + $run_test
    $run_test += " openldap2-ssl"
  else
    $run_test += " openldap2"
  end
end
$run_test += " #{$slapd} #{$schema_dir}"


File.open("Makefile","a"){|f|
  f.print <<EOF

test::
\t#{$run_test}

testclean: test-clean

test-clean::
\t(cd $(srcdir); /bin/sh test/test.sh clean)

reconfig::
\t$(RUBY_INSTALL_NAME) $(srcdir)/extconf.rb #{ARGV.join(" ")}

doc:
#\t$(RUBY_INSTALL_NAME) -rrdoc/ri/ri_paths -e 'puts RI::Paths::PATH[0]'
\trdoc --ri-site *.c lib/ldap

unit:
\t(cd test; $(RUBY_INSTALL_NAME) tc_ldif.rb)

.PHONY:	doc
EOF
}
