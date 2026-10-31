---
title: "Default Landing Page"
description: "Choose the page DefectDojo Pro opens after you sign in"
audience: pro
weight: 7
---

Your **Default Landing Page** is the page DefectDojo Pro opens after you sign in. Set it on your **User Profile** page: select your username at the bottom of the sidebar, then **User Profile**, and find the field under **Signing In**.

The landing page is saved to your account, not to the browser, so it follows you to every browser and device you sign in from.

## Choosing a page

When no page is chosen, signing in opens **Home**, as it always has.

The list holds every page in the sidebar that your account can open, named by where it sits in the menu (for example **Explore > Findings > All**). Type in the list to filter it. Clear the field to go back to Home. Select **Submit** to save it with the rest of your profile. A change takes effect the next time you sign in, in any browser.

## When it applies

The landing page applies when signing in has nowhere else to go:

- After signing in from the sign-in page, including single sign-on, multi-factor verification and a required password change.
- After a single sign-on started from your identity provider (an app tile in its portal, for example). An administrator who sets `DD_LOGIN_REDIRECT_URL` to another page sends these sign-ins there instead.
- When your session ended while you were on Home, or you open a bookmark of it.

When you were sent to the sign-in page from a specific page (a link to a finding, for example), signing in takes you back to that page instead.

If your landing page later becomes unavailable to you (a role is removed, the feature behind it is turned off, or a [sidebar preset](/navigation/pro__sidebar_presets/) hides it), signing in opens Home instead, without an error. The profile page says so when the preset you picked hides it.

## Turning it off

The field is controlled by the **Default Landing Page** feature flag (see [Feature Flags](/admin/feature_flags/pro__feature_flags/)), which is on by default. While it is off, the field is hidden and signing in opens Home. Saved landing pages are kept, and apply again when the flag is turned back on.
