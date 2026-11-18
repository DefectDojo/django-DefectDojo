---
title: "Landing Page"
description: "Choose the page DefectDojo Pro opens after you sign in"
audience: pro
weight: 7
---

Your **Landing Page** is the page DefectDojo Pro opens after you sign in. Set it on your **User Profile** page: select your username at the bottom of the sidebar, then **User Profile**, and find the field under **Signing In**.

The landing page is saved to your account, not to the browser, so it follows you to every browser and device you sign in from.

## Choosing a page

When no page is chosen, signing in opens the landing page from your Default Profile or the Instance Default if one is set (see [Default Profile and instance defaults](#default-profile-and-instance-defaults)), and **Home** otherwise. Your profile names where that page comes from, as **From <profile>: <value>** or **Instance Default: <value>**.

The list holds every page in the sidebar that your account can open, named by where it sits in the menu (for example **Explore > Findings > All**). Type in the list to filter it. Clear the field to go back to Home. Select **Submit** to save it with the rest of your profile. A change takes effect the next time you sign in, in any browser.

## Default Profile and instance defaults

When you have not chosen a landing page, signing in opens the landing page from the first source that sets one and that you can open: the [Default Profile](/admin/user_management/create_user_group/#defaults) assigned to you directly, then your Groups' Default Profiles in rank order, then the **Instance Landing Page**, then Home. Profiles do not combine: the first profile that sets a landing page wins. An administrator sets the Instance Landing Page on **Settings > Defaults > Instance Defaults** (empty means Home). When a profile's landing page is not available to you, the next default applies. The landing page is not a layout, so restricting layout customization never replaces a landing page you chose.

A Default Profile can also lock its landing page (**Lock Landing Page** on the profile). While the first profile in that order whose landing page you can open has it locked, signing in always opens that page, your own choice is set aside, and the **Landing Page** field on your profile is read-only and reads **Set by <profile>**. If you cannot open the locked page, the next default applies and you can choose your own again. Superusers are never locked.

## When it applies

The landing page applies when signing in has nowhere else to go:

- After signing in from the sign-in page, including single sign-on, multi-factor verification and a required password change.
- After a single sign-on started from your identity provider (an app tile in its portal, for example). An administrator who sets `DD_LOGIN_REDIRECT_URL` to another page sends these sign-ins there instead.
- When your session ended while you were on Home, or you open a bookmark of it.

When you were sent to the sign-in page from a specific page (a link to a finding, for example), signing in takes you back to that page instead.

If your landing page later becomes unavailable to you (a role is removed, the feature behind it is turned off, or a [sidebar preset](/navigation/pro__sidebar_presets/) hides it), signing in opens Home instead, without an error. The profile page says so when the preset you picked hides it.

## Turning it off

The field is controlled by the **Default Landing Page** feature flag (see [Feature Flags](/admin/feature_flags/pro__feature_flags/)), which is on by default. While it is off, the field is hidden and signing in opens Home. Saved landing pages are kept, and apply again when the flag is turned back on.
