/* Rules written for this fixture only. They match placeholder strings in the sample files next to
   them, so nothing here depends on a real detection ruleset. */

rule Suspicious_Reverse_Shell_Command
{
    meta:
        description = "Shell command that reconnects to an attacker-controlled host"
        severity = "high"
        author = "generic-ruleset"
        reference = "https://example.com/rules/reverse-shell"
        date = "2026-07-31"
    strings:
        $bash = "bash -i >& /dev/tcp/"
        $nc = "nc -e /bin/sh"
    condition:
        any of them
}

rule Hardcoded_Placeholder_Credential
{
    meta:
        description = "Credential assigned inline in a configuration file"
        severity = "medium"
        author = "generic-ruleset"
    strings:
        $a = "password = \"CHANGEME\""
        $b = "api_key = \"AKIAPLACEHOLDER\""
    condition:
        any of them
}

rule Debug_Endpoint_Left_Enabled
{
    meta:
        description = "Debug endpoint reachable in a shipped configuration"
        severity = "low"
    strings:
        $ = "debug_endpoint=enabled"
    condition:
        all of them
}

rule Unrated_Marker_String
{
    /* No severity in the metadata, so the parser has to fall back to a default. */
    meta:
        description = "Marker with no severity recorded in the rule"
    strings:
        $ = "GENERIC-MARKER-9F2A"
    condition:
        all of them
}

rule Rule_With_No_Metadata_At_All
{
    strings:
        $ = "NO-METADATA-MARKER"
    condition:
        all of them
}

rule Awkward_Metadata_Values
{
    /* A description holding a comma and an escaped quote, plus non-string metadata: all of these
       have to survive being printed as one bracketed list by "yara -m". */
    meta:
        description = "Matches a marker, then reports it as \"awkward\""
        severity = "critical"
        confidence = 90
        experimental = true
    strings:
        $ = "AWKWARD-MARKER"
    condition:
        all of them
}
