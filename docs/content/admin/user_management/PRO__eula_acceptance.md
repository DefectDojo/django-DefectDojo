---
title: "End User License Agreement"
description: "Each person accepts the DefectDojo Pro End User License Agreement once, after they first sign in"
audience: pro
weight: 4
---

Use of DefectDojo Pro is subject to DefectDojo Inc.'s [End User License Agreement](https://defectdojo.com/eula) (EULA). Your organization's subscription agreement (the Master Subscription Agreement accepted at checkout, on a quote or on signed paper) still governs the organization. The EULA binds each person who uses DefectDojo Pro, so every person accepts it themselves.

## Accepting the agreement

The first time a person signs in, DefectDojo Pro shows one card before anything else loads. It holds the full text of the agreement, its version and a link to the published copy at [defectdojo.com/eula](https://defectdojo.com/eula), and one **I Agree** button. Nothing else in the application opens until they select it. Selecting **Logout** on the card leaves without accepting.

The card appears after every way of signing in: a username and password, OIDC and the social login providers, SAML (including sign-ins your identity provider starts), and remote user authentication. When MFA is required, the person completes MFA first and then sees the card.

A person accepts each version once. When DefectDojo publishes a new version of the agreement, everyone sees the card again at their next request after the upgrade that carries it.

The text on the card ships with DefectDojo Pro, so an instance without internet access shows exactly the published version.

## Forced password resets

When an administrator has set **Force Password Reset** on an account (see [Resetting User Credentials](../pro__resetting_user_credentials/)), and that person has not accepted the current version yet, the agreement appears on the **Change Password** page as a checkbox below the password fields, with the full text above it. Setting the new password and accepting the agreement is one step.

## Who is not asked

* **API tokens.** A request made with an API token is never held for the agreement, so CI pipelines, the DefectDojo GitHub Action and the MCP server keep working.
* **[Service users](../pro__service_users/).** A service user cannot sign in to the UI, so it is never asked.

The shared `admin` account is asked like any other account. Each person who signs in with it accepts on behalf of that account; we recommend giving every person their own account.

## The record

DefectDojo Pro records each acceptance with the agreement version, the time, the IP address and browser it came from, and how the person signed in. It also sends the acceptance to DefectDojo, so the record survives when an instance's data is deleted. An instance that cannot reach DefectDojo keeps trying, and an air-gapped instance keeps the local record only.

## Footer

The footer of every page, and of the login page, reads "Use of DefectDojo Pro is subject to DefectDojo Inc.'s End User License Agreement." with a link to the published agreement.
