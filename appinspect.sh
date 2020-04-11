#!/bin/bash

splunk-appinspect inspect `ls TA-jira-service-desk-simple-addon_*.tgz | head -1` --mode precert --included-tags cloud

