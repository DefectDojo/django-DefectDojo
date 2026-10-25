---
title: "Unmanaged Devices"
description: "Devices your EDR sees on the network that have no agent of its own, reported by the CrowdStrike Falcon and Microsoft Defender connectors"
weight: 12
audience: pro
---

**Unmanaged Devices** lists the devices your endpoint security tool sees on your network that do not run its agent: printers, phones, cameras, network gear, and servers and laptops nobody onboarded. Your EDR already finds them, because its agents watch the network around them. DefectDojo collects those lists from the connectors you already run, so you can see the gap in one place.

> Unmanaged Devices is a beta feature. Turn on **Unmanaged Devices** on the [Feature Flags page](/admin/feature_flags/pro__feature_flags/), then turn on **Report Unmanaged Devices** on each connection that should send its list.

## Where the devices come from

| Connector | What it reports | What it needs |
|---|---|---|
| [CrowdStrike Falcon](/connectors/toolreference/crowdstrike_falcon/#unmanaged-devices) | Hosts Falcon Discover found that have no Falcon sensor | A Falcon Discover subscription, and the **Assets: Read** scope on the API client |
| [Microsoft Defender](/connectors/toolreference/microsoft_defender/#unmanaged-devices) | Machines Defender for Endpoint discovered that are not onboarded | The **Machine.Read.All** application permission on the app registration |

Each sync sends the connection's complete list. A device the source stops reporting is marked **Stale** with the time it went missing. It is never deleted, and it becomes **Active** again if the source reports it later.

If the source refuses the request (a missing permission or subscription), the connection logs a warning and sends nothing, so an access problem never empties the list.

## What each device shows

- **Name**: the hostname, or the fully qualified name, or the source's own id when the source knows no name.
- **IP and MAC addresses** the source has seen for the device.
- **OS, device type and manufacturer**, as the source classifies them.
- **How found**: **Passive** when the source learned about the device by listening, **Active** when it probed for it.
- **Confidence**: CrowdStrike's confidence score for the device, when it gives one.
- **Onboarding status**: Defender's own answer to whether the device could take its agent: **Can be onboarded**, **Unsupported**, or **Insufficient info**. CrowdStrike devices show **Unmanaged**.
- **First and last seen**, as the source reports them.

## Dismissing a device

A device you have looked at and do not need to act on can be dismissed from its row menu. Dismissed devices stay dismissed across syncs and can be restored at any time. Dismissing and restoring needs the **Connector Edit** permission; seeing the list needs **Connector View**.

## What unmanaged devices are not

- **They are not Assets.** Nothing on this list creates an Asset or changes an existing one.
- **They are not Findings.** Devices do not count toward Total Findings.
