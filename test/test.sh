#!/bin/sh

TEST=`dirname $0`
RUBY=$1
echo $SRCDIR
LOGFILE=test.log
SERVERLOG=serv.log
SSLDIR=$TEST/ssl
OPENSSL=openssl
LDAPSEARCH=ldapsearch
LDAPCONF=./test-db/slapd.conf
OPENSSLCONF="-config $TESTDIR/openssl/openssl.cnf"

# initialize DB
mkdir -p ./test-db

SCRIPTS="$TEST/bind.rb \
         $TEST/add.rb \
         $TEST/add2.rb \
         $TEST/add3.rb \
         $TEST/search.rb \
         $TEST/search2.rb \
         $TEST/search3.rb \
	 $TEST/search4.rb \
	 $TEST/search5.rb \
         $TEST/modrdn.rb \
         $TEST/search2.rb \
         $TEST/delete.rb \
	 $TEST/search2.rb \
         $TEST/compare.rb \
         $TEST/ext.rb \
         $TEST/misc1.rb \
         $TEST/misc2.rb"

print_usage(){
  echo "$0 <ruby> {openldap1|openldap2|openldap2-ssl|newcert|clean} <slapd> <schema-dir>"
}


if [ x"$4" = x"" ]
then
  LDAPSCHEMADIR=
else
  LDAPSCHEMADIR=$4
fi

if [ x"$3" = x"" ]
then
  LDAPD=slapd
else
  LDAPD=$3
fi

case "$2" in
'clean')
  rm -rf $LOGFILE $SERVERLOG $SSLDIR $LDAPCONF
  exit 0
  ;;
'openldap1')
  # for OpenLDAP1
  TESTDIR=$TEST/openldap1
  LDAPCONFIN=$TESTDIR/slapd.conf.in
  DBDIR=./test-db
  PIDFILE=$DBDIR/slapd.pid
  PORT=6666
  LDAPURL="ldap://localhost:$PORT/"
  LDAPDOPT="-d 2 -f $LDAPCONF -h \"$LDAPURL\""
  LDAPDCMD="$LDAPD $LDAPDOPT"
  ;;
'openldap2')
  # for OpenLDAP2
  TESTDIR=$TEST/openldap2
  LDAPCONFIN=$TESTDIR/slapd.conf.in
  DBDIR=./test-db
  PIDFILE=$DBDIR/slapd.pid
  PORT=6666
  LDAPURL="ldap://localhost:$PORT/"
  LDAPDOPT="-d 2 -f $LDAPCONF -h \"$LDAPURL\""
  LDAPDCMD="$LDAPD $LDAPDOPT"
  SCRIPTS="$SCRIPTS $TEST/subschema.rb"
  ;;
'openldap2-ssl')
  # -- experimental -- OpenLDAP2 with SSL,SASL
  TESTDIR=$TEST/openldap2
  LDAPCONFIN=$TESTDIR/slapd-ssl.conf.in
  DBDIR=./test-db
  PIDFILE=$DBDIR/slapd.pid
  PORT=6666
  SSLPORT=6667
  LDAPURL="ldaps://localhost:$SSLPORT/ ldap://localhost:$PORT/"
  LDAPDOPT="-d127 -f $LDAPCONF -h \"$LDAPURL\""
  LDAPDCMD="$LDAPD $LDAPDOPT"
  SCRIPTS="$SCRIPTS $TEST/subschema.rb $TEST/bind-ssl.rb $TEST/bind-ldaps.rb"
  ;;
'newcert')
  openssl req -new -x509 -out ./test-db/server.pem \
          -nodes -keyout ./test-db/server.pem \
	  -config $TEST/openssl/openssl.cnf
  exit 0
  ;;
*)
  print_usage
  exit
  ;;
esac

# create slapd.conf
echo $LDAPCONF
$RUBY -p -e "gsub(/%LDAPSCHEMADIR%/, \"$LDAPSCHEMADIR\")" < $LDAPCONFIN > $LDAPCONF

error(){
  echo $@ 1>&2
}

runruby(){
  echo "-- $RUBY $1 $PORT $SSLPORT --" >> $LOGFILE
  $RUBY $1 $PORT $SSLPORT 1>> $LOGFILE 2>> $LOGFILE
}

rundebug(){
  echo "run $1 $PORT $SSLPORT"
  gdb $RUBY
}

# start slapd
rm -f $LOGFILE
rm -f $SERVERLOG

eval $LDAPDCMD 1>> $SERVERLOG 2>> $SERVERLOG &
echo $LDAPDCMD

while [ ! -f "$PIDFILE" ]; do
  echo "waiting for ldapd"
  sleep 1
done


if [ -f "$LOGFILE" ]; then
  rm $LOGFILE
fi

echo -n "Do you want to run scripts?[y/n]"
read ans
case "$ans" in
y*|Y*)
  RESULT=ok
  for f in $SCRIPTS
  do
    printf "running $f .... "
    if runruby $f; then
      echo "succeed"
    else
      echo "fail"
      RESULT=error
      runruby $f
      rundebug $f
    fi
  done
  ;;
*)
  echo -n "Press any key to stop the server."
  read ans
  ;;
esac

# $LDAPSEARCH -b "o=JAIST, c=JP" -h localhost -p $SSLPORT -Z "(objectclass=*)"

# stop slapd
kill -TERM `cat $PIDFILE`
rm -rf $DBDIR
