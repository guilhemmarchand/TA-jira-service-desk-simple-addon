.. TA-jira-service-desk-simple-addon documentation master file, created by
   sphinx-quickstart on Tue Sep 18 23:25:46 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to the Splunk Add-on for JIRA Atlassian Service Desk application documentation
======================================================================================

**The Splunk Add-on for JIRA Atlassian Service Desk provides alerts action for JIRA issues creation:**

- Trigger JIRA issue creation from Splunk core alerts and Enterprise Security correlation searches
- Dynamic retrieval per JIRA project for types of issues and priority
- Dynamic assignment of priority (optional)
- Dynamic and/or static assignment of summary, description, assignee and labels
- Custom fields full capabilities via the embedded custom field structure in alerts (optional)
- Deduplication feature workflow with bi-directional integration, allows detecting a duplication issue creation request, and adding new comments automatically instead of creating duplicated issues
- Attaching Splunk alert results to the JIRA issue in CSV or JSON format
- Resilient store JIRA issue creation, shall a JIRA issue fails to be created, the resilient workflow handles automatic retries with a resilient policy
- Monitoring of JIRA issue workflow via the embedded Overview dashboard and out of the box alerts
- Get any information from JIRA via the REST API custom command wrapper, generate and index to summary events or the metric store issues statistics per projects

.. image:: img/screenshot.png
   :alt: screenshot.png
   :align: center
   :width: 1200px

.. image:: img/screenshot_projects.png
   :alt: screenshot_projects.png
   :align: center
   :width: 1200px

.. image:: img/screenshot_api.png
   :alt: screenshot_api.png
   :align: center
   :width: 1200px

.. image:: img/screenshot1.png
   :alt: screenshot1.png
   :align: center
   :width: 800px

Overview:
=========

.. toctree::
   :maxdepth: 2

   about
   compatibility
   support
   download

Deployment and configuration:
=============================

.. toctree::
   :maxdepth: 2

   deployment
   configuration

User guide:
===========

.. toctree::
   :maxdepth: 2

   userguide

Troubleshoot:
=============

.. toctree::
   :maxdepth: 1

   troubleshoot

Versions and build history:
===========================

.. toctree::
   :maxdepth: 1

   releasenotes.rst
