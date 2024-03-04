---
title: "Bearer CLI"
toc_hide: true
---

### File Types
DefectDojo parser accepts a .json file.

To export a .json file from Bearer CLI, pass "-f json" to your Bearer command  
See Bearer documentation: https://docs.bearer.com/reference/commands/

### Sample Scan Data
Sample Bearer scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/bearer)

### Acceptable JSON Format

~~~

{
    "critical": [
        {
            "cwe_ids": [
                "328"
            ],
            "id": "php_lang_weak_hash_md",
            "title": "Usage of weak hashing library (MDx)",
            "description": "## Description\n\nA weak hashing library can lead to data breaches and greater security risk.\n\n## Remediations\n\nAccording to [OWASP](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/04-Testing_for_Weak_Encryption), MD5 is considered a weak hashing algorithms and therefore shouldn't be used.\n\n❌ Avoid libraries and algorithms with known weaknesses:\n\n```php\n  $encrypted = md5($input)\n```\n\n✅ Use stronger encryption algorithms when storing data.\n\n```php\n  $encrypted = hash('sha256', $input)\n```\n",
            "documentation_url": "https://docs.bearer.com/reference/rules/php_lang_weak_hash_md",
            "line_number": 31,
            "full_filename": "demo.php",
            "filename": "demo.php",
            "category_groups": [
                "PII",
                "Personal Data",
                "Personal Data (Sensitive)"
            ],
            "source": {
                "start": 31,
                "end": 31,
                "column": {
                "start": 20,
                "end": 78
                }
            },
            "sink": {
                "start": 31,
                "end": 31,
                "column": {
                "start": 20,
                "end": 78
                },
                "content": "content"
            },
            "parent_line_number": 31,
            "snippet": "content",
            "fingerprint": "d150ed2257371d33a3ff618d13e5b9a8_0",
            "old_fingerprint": "ac8bb3963b25ad44bebea06c9978fc58_5",
            "code_extract": "                && content == $compParts[3]"
        }
    ],
    "high": [
    
    ],
    "medium": [
    
    ],
    "low": [
    
    ]
}

~~~