#!/usr/bin/env bash
# set -x

PWD=`pwd`
app="TA-jira-service-desk-simple-addon"
version=`grep 'version =' TA-jira-service-desk-simple-addon/default/app.conf | head -1 | awk '{print $3}' | sed 's/\.//g'`

find . -name "*.pyc" -type f -exec rm -f {} \;
rm -f *.tgz
tar -czf ${app}_${version}.tgz --exclude=TA-jira-service-desk-simple-addon/local --exclude=TA-jira-service-desk-simple-addon/metadata/local.meta --exclude=TA-jira-service-desk-simple-addon/lookups/lookup_file_backups TA-jira-service-desk-simple-addon
echo "Wrote: ${app}_${version}.tgz"

exit 0

