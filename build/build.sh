#!/usr/bin/env bash
# set -x

# for Mac OS X
export COPYFILE_DISABLE=true

PWD=`pwd`
app="TA-jira-service-desk-simple-addon"
cp -a ../${app} .
version=`grep 'version =' ${app}/default/app.conf | head -1 | awk '{print $3}' | sed 's/\.//g'`

find . -name "*.pyc" -type f -exec rm -f {} \;
rm -f *.tgz
tar -czf ${app}_${version}.tgz --exclude=${app}/local --exclude=${app}/metadata/local.meta --exclude=${app}/lookups/lookup_file_backups ${app}
echo "Wrote: ${app}_${version}.tgz"

sha256=$(sha256sum ${app}_${version}.tgz)
echo "Wrote: ${sha256}"
echo ${sha256} > release-sha256.txt

rm -rf ${app}

exit 0