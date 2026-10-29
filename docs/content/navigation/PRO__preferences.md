---
title: "Preferences"
description: "Choose the page DefectDojo Pro opens after you sign in, and the dashboard the Dashboards page opens with"
audience: pro
weight: 7
---

The **Preferences** page holds the choices that shape how DefectDojo Pro opens for you. Open it from the account menu: select your username at the bottom of the sidebar, then **Preferences**. It is at `/ui/user/preferences`.

Your preferences are saved to your account, not to the browser, so they follow you to every browser and device you sign in from.

## Default Landing Page

The page shown after you sign in. When none is chosen, signing in opens **Home**, as it always has.

The list holds every page in the sidebar that your account can open, named by where it sits in the menu (for example **Explore > Findings > All**). Type in the list to filter it. Clear the field to go back to Home.

The landing page applies when signing in has nowhere else to go:

- After signing in from the sign-in page, including single sign-on, multi-factor verification and a required password change.
- After a single sign-on started from your identity provider (an app tile in its portal, for example). An administrator who sets `DD_LOGIN_REDIRECT_URL` to another page sends these sign-ins there instead.
- When your session ended while you were on Home, or you open a bookmark of it.

When you were sent to the sign-in page from a specific page (a link to a finding, for example), signing in takes you back to that page instead.

If your landing page later becomes unavailable to you (a role is removed, or the feature behind it is turned off), signing in opens Home instead, without an error.

## Default Dashboard

The dashboard the **Dashboards** page opens with. The list holds the dashboards you own and the collaborative shared dashboards, the same choices as **Set Default** under **Manage Layouts** on the Dashboards page (see [Customizable Dashboards](/metrics_reports/dashboards/pro__custom_dashboards/#sharing-cloning-and-defaults)). Either place changes the same setting.

This field appears only when Customizable Dashboards are enabled. When an administrator has turned on **Restrict Layout Customization**, the field shows the dashboard they designated and cannot be changed.

## Saving

Select **Submit** to save both choices. A change to your landing page takes effect the next time you sign in, in any browser.

## Turning the page off

The page is controlled by the **Preferences Page** feature flag (see [Feature Flags](/admin/feature_flags/pro__feature_flags/)), which is on by default. While it is off, the page and its account menu entry are hidden and signing in opens Home. Saved landing pages are kept, and apply again when the flag is turned back on.
