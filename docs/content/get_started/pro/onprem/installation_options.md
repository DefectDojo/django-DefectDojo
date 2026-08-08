---
title: "Self-Hosting DefectDojo Pro"
date: 2021-02-02T20:46:29+01:00
weight: 5
audience: pro
---

DefectDojo Pro can be fully self-hosted in your own environment, giving you control over your infrastructure, data, and security posture. It suits organizations with compliance, data residency, or internal security requirements that rule out a hosted deployment, and it delivers the same capabilities as the cloud-hosted product.

This page covers the deployment models available, what you need before you start, and where the rest of this section fits.

## Two deployment models

**Docker Compose on a single host** is the simpler of the two. The application, the async workers, and the cache all run on one machine, managed by a command line tool we provide. Because nothing in that arrangement scales out, the host has to be sized for your peak rather than your average, and for most deployments the peak is a large scan import arriving while people are working in the UI.

**Kubernetes, using our Helm chart**, runs those same components as separate workloads. That lets you provision for steady state and add replicas when load arrives, and it lets you scale the part that is actually busy instead of the whole machine.

Both models use PostgreSQL. For production we recommend an external managed database, which is what the Helm chart assumes by default. The Compose tooling can also run PostgreSQL in a container alongside the application, which is convenient for evaluation and not what you want for production data.

If you already run Kubernetes, use it. A single host works perfectly well, and plenty of deployments run that way, but you end up buying headroom you cannot reallocate. If you do not run Kubernetes and do not want to, Compose is a legitimate choice rather than a compromise.

## Before you start

Size the deployment first. Both models depend on knowing roughly how many findings you expect to hold and how many people will be working in the product at once, and those two numbers drive different parts of the deployment. The hardware sizing guidance in this section covers both.

You will need a license file and the deployment tooling for your chosen model. DefectDojo provides both when your subscription begins. If you do not have them, or you need them reissued, contact your account representative or [support@defectdojo.com](mailto:support@defectdojo.com).

You will also need somewhere to run it, a PostgreSQL database it can reach, and a hostname that resolves to the deployment. The individual installation pages cover the specifics for each model.

## What else is in this section

The pages alongside this one cover the rest of the lifecycle. There is sizing guidance for choosing hardware, instructions for moving an existing open source instance into a self-hosted Pro deployment, and a procedure for installing where the target host has no route to the internet.

For deployments already running, there are pages on upgrading, on backing up, on raising the limits that reject large scan uploads, and on expanding storage for uploaded files when a host runs short. Use the section navigation to browse them.

## Questions

If you are weighing the two models for your environment, or your circumstances do not resemble the assumptions here, we would rather talk it through before you provision than after.

Existing customers should contact their account representative or [support@defectdojo.com](mailto:support@defectdojo.com). If you are evaluating DefectDojo Pro and want to discuss self-hosting, reach us at [hello@defectdojo.com](mailto:hello@defectdojo.com).
