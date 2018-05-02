#!/bin/sh

which xxd 1>/dev/null 2>/dev/null
if [ $? -ne 0 ]; then
	echo "xxd is not installed !!!"
	exit 1
fi;

if [ -z $TMPDIR ]; then
	if [ ! -z $TMP ]; then
		TMPDIR=$TMP
	else
		TMPDIR=/tmp
	fi;
fi;

for i in `seq 1 100`; do
	KEY=`dd if=/dev/urandom bs=32 count=1 2>/dev/null | xxd -p - | tr -d '\n'`
	dd if=/dev/urandom bs=$i count=1 > $TMPDIR/cryptofile_test 2>/dev/null
	./cryptofile enc $KEY $TMPDIR/cryptofile_test $TMPDIR/cryptofile_test.enc
	./cryptofile dec $KEY $TMPDIR/cryptofile_test.enc $TMPDIR/cryptofile_test.enc.dec
	cmp $TMPDIR/cryptofile_test $TMPDIR/cryptofile_test.enc.dec
	if [ $? -ne 0 ]; then
		echo "test[$i] FAILED"
		echo
		cp $TMPDIR/cryptofile_test .
		cp $TMPDIR/cryptofile_test.enc .
		cp $TMPDIR/cryptofile_test.enc.dec .
		echo "Please send me cryptofile_test[.enc[.dec]] files for debug why a test failed."
		exit 1
	else
		echo "test[$i] OK"
	fi;

done;

rm $TMPDIR/cryptofile_test
rm $TMPDIR/cryptofile_test.enc
rm $TMPDIR/cryptofile_test.enc.dec
