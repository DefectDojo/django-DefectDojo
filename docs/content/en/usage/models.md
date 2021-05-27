---
title: "Core data classes"
description: "DefectDojo is based on a model that allows high flexibility for your test tracking needs."
draft: false
weight: 1
---

![Data Model](../../images/DD-Hierarchy.svg)

## Product Type

Product types represent the top level model, these can be business unit
divisions, different offices or locations, development teams, or any
other logical way of distinguishing "types" of products.

Examples:
:   -   IAM Team
    -   Internal / 3rd Party
    -   Main company / Acquisition
    -   San Francisco / New York offices

## Product

This is the name of any project, program, or product that you are
currently testing.

Examples:
:   -   Wordpress
    -   Internal wiki
    -   Slack

## Engagement

Engagements are moments in time when testing is taking place. They are
associated with a name for easy reference, a time line, a lead (the user
account of the main person conducting the testing), a test strategy, and
a status. Engagement consists of two types: Interactive and CI/CD. An
interactive engagement is typically an engagement conducted by an
engineer, where findings are usually uploaded by the engineer. A CI/CD
engagement, as it's name suggests, is for automated integration with a
CI/CD pipeline.

Examples:
:   -   Beta
    -   Quarterly PCI Scan
    -   Release Version X

## Test

Tests are a grouping of activities conducted by engineers to attempt to
discover flaws in a product. Tests are bundled within engagements, have a 
start and end date and are defined by a test type.

Examples:
:   -   Burp Scan from Oct. 29, 2015 to Oct. 29, 2015
    -   Nessus Scan from Oct. 31, 2015 to Oct. 31, 2015
    -   API Test from Oct. 15, 2015 to Oct. 20, 2015

## Finding

A finding represents a flaw discovered while testing. It can be
categorized with severities of Critical, High, Medium, Low, and
Informational (Info).

Examples:
:   -   OpenSSL 'ChangeCipherSpec' MiTM Potential Vulnerability
    -   Web Application Potentially Vulnerable to Clickjacking
    -   Web Browser XSS Protection Not Enabled

## Endpoint

Endpoints represent testable systems defined by their IP address or Fully Qualified Domain Name.

Examples:
:   -   https://www.example.com
    -   https://www.example.com:8080/products
    -   192.168.0.36
