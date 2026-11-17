---
title: "Sensor Telemetry Sharing"
description: "Opt in to share anonymized sensor hit events with DefectDojo, and see what your sensors contributed"
weight: 11
audience: pro
draft: false
---

> **Not yet available:** Sensor Telemetry Sharing cannot be turned on yet, on DefectDojo Cloud or on a self-hosted instance, whatever its configuration. This page describes how it will work once it is released.

Sensor Telemetry Sharing lets an instance send anonymized **sensor hit events** to DefectDojo's threat intelligence service. A hit is one detection by a sensor on your hosts that is tied to a CVE. Shared hits tell the intelligence service which vulnerabilities are being exploited in the wild, and that evidence reaches every instance through the Threat Intelligence feed.

Sharing is a **DefectDojo Pro** feature. It is **off by default**, and nothing is sent until a superuser turns it on.

## What is shared, and what is not

Each event holds four values and nothing else:

| Field | What it is |
| --- | --- |
| CVE | The CVE the detection rule that matched is tagged with |
| Time | The hour the hit was seen, in UTC. Minutes and seconds are not sent |
| Source | At most the country and the network (ASN) the hit came from. Often empty |
| Contributor ID | A random identifier that changes every calendar month |

An event never holds a payload or request body, a hostname, an IP address, a user name, a command line, an asset name, a company name, the name or identifier of the detection rule, or the name or URL of your instance. A source is filled in only when your instance is set up to look one up, and only for a public address. DefectDojo then works out the country and network on your instance and discards the address there, before anything is sent.

Rule identifiers are left out on purpose: a rule you wrote yourself can carry any name, including your company's, a host's or a person's.

Events are delivered to DefectDojo with your instance's license key, which is how the intelligence service accepts them. The key travels with the delivery, not inside the events.

The contributor ID lets the intelligence service count how many different instances saw a CVE within a month. It is drawn at random, a new one replaces it each month, and the old one cannot be worked out from the new one.

Only hits from after you turned sharing on, and from the last 24 hours, are sent. Turning sharing off deletes every event that was still waiting to be sent and discards the contributor ID, and so does a change of the contract term. Turning sharing on again starts with a new contributor ID.

## Before you can turn it on

Sharing is covered by a term in your DefectDojo contract. The card names the **contract term version** you accept by turning sharing on, and sharing cannot be turned on until that version is available on your instance.

The contract term will be published before sharing becomes available.

If DefectDojo later publishes a new version of the term, sharing pauses on its own. The card says so, the events waiting under the old version are deleted, and nothing is sent until a superuser turns sharing on again under the new version. The checkbox starts cleared while sharing is paused, so the new version is accepted only by selecting it again. Sharing then starts afresh, with a new contributor ID.

Sharing is never available on an air-gapped instance, on the public demo, or in the sandbox.

## Turn sharing on or off

1. Sign in as a superuser and open **Settings > System Settings**.
2. Scroll to the **Sensor Telemetry** card at the bottom of the page.
3. Read what is shared and the contract term version the card names. When your instance has the term's address, the card links to it next to the version (**Read the contract term**).
4. Select **Share Sensor Hit Events**, then **Submit**. Clear the checkbox and select **Submit** to stop.

Every change is recorded in the audit log with the user who made it.

## What the card shows

* **Sharing**: Off, On, Paused (the contract term changed), On, Not Sending (no intelligence endpoint or no license key is configured; the card says which), or Not Available.
* **Events Shared**, **Events Waiting** and **Events Dropped**: how many events were delivered, are queued, or were discarded. An event that cannot be delivered is retried for up to a day and then dropped.
* **Last Shared**: when events were last delivered.
* **The CVE list**: the CVEs your sensors observed, up to the 200 seen most recently, with the number of hits, how many were shared, and when each was first and last seen. The card's title shows how many CVEs were observed in all. This list is kept on your instance whether or not sharing is on.
* **Seen Elsewhere**: whether other sharing instances saw the same CVE. It is filled in only while sharing is on and the intelligence service answers, and only for CVEs your instance has already shared: asking names the CVE, so a CVE seen only before you turned sharing on is never asked about. Otherwise the line under the table says why it is empty, for example that no intelligence endpoint or license key is configured on the instance.

The card appears once your instance has sensors, has observed a CVE, or has been configured for sharing.

## Self-hosted configuration

On a self-hosted instance the operator sets these environment variables. All are blank by default, and blank means off.

| Variable | Purpose |
| --- | --- |
| `DD_SENSOR_TELEMETRY_CONTRACT_TERM_VERSION` | The version of the contract term. Without it, sharing cannot be turned on |
| `DD_SENSOR_TELEMETRY_CONTRACT_TERM_URL` | Optional. The HTTPS address where the contract term can be read. The card links to it next to the version |
| `DD_SENSOR_TELEMETRY_ENDPOINT` | The intelligence service's HTTPS base URL. Without it, no network call is ever made |
| `DD_THREAT_INTEL_LICENSE_KEY` | The license key sent with each delivery. Without it, no network call is made |
| `DD_SENSOR_TELEMETRY_SOURCE_RESOLVER` | Optional. The dotted Python path of a function that turns a public source address into a country and ASN. DefectDojo ships no country or ASN database, so without it events carry no source |
