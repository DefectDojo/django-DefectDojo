---
title: "Nosey Parker"
toc_hide: true
---
Input Type:
-
This parser takes JSON Lines Output from Nosey Parker. Supports version 0.15.0 of https://github.com/praetorian-inc/noseyparker 

Things to note about the Nosey Parker Parser:
- 
- All findings are marked with a severity of 'High'
- The deduplication algorithm marks a unique finding by the secret, filepath, and line number all together

Acceptable JSON Lines file:
-
Each line of the JSON Lines file from NoseyParker is one secret, but it can have multiple matches within the repository. All properties are required by the parser.

The following is an example of an acceptable JSON lines file:
~~~
{"type":"finding","rule_name":"Generic API Key","match_content":"32ui1ffdasfhu239b4df2ac6609a9919","num_matches":1,"matches":[{"provenance":[{"kind":"file","path":"./app/schema/config.py"},{"kind":"git_repo","repo_path":"./.git","commit_provenance":{"commit_kind":"first_seen","commit_metadata":{"commit_id":"0ee84b84c29924b210e3576fe9d1e8632948bedc","committer_name":"Princess Leia","committer_email":"leia@test.com","committer_timestamp":"1685495256 +0000","author_name":"Princess Leia","author_email":"leia@test.com","author_timestamp":"1685495256 +0000","message":"framework\n"},"blob_path":"app/schema/config.py"}}],"blob_metadata":{"id":"0ee84b84c29924b210e3576fe9d1e8632948bedc","num_bytes":664,"mime_essence":"text/plain","charset":null},"blob_id":"0ee84b84c29924b210e3576fe9d1e8632948bedc","location":{"offset_span":{"start":617,"end":660},"source_span":{"start":{"line":16,"column":17},"end":{"line":16,"column":59}}},"capture_group_index":1,"match_content":"32ui1ffdasfhu239b4df2ac6609a9919","snippet":{"before":"E = \"https://testwebsite.com\"\n ","matching":"API_KEY = \"32ui1ffdasfhu239b4df2ac6609a9919","after":"\"\n\n\n"},"rule_name":"Generic API Key"}]}
{"type":"finding","rule_name":"Generic Username and Password (unquoted)","match_content":"secret","num_matches":1,"matches":[{"provenance":[{"kind":"file","path":"./app/schema/config.py"},{"kind":"git_repo","repo_path":"./.git","commit_provenance":{"commit_kind":"first_seen","commit_metadata":{"commit_id":"0ee84b84c29924b210e3576fe9d1e8632948bedc","committer_name":"Princess Leia","committer_email":"leia@test.com","committer_timestamp":"1685495256 +0000","author_name":"Princess Leia","author_email":"leia@test.com","author_timestamp":"1685495256 +0000","message":"framework\n"},"blob_path":"app/schema/config.py"}}],"blob_metadata":{"id":"0ee84b84c29924b210e3576fe9d1e8632948bedc","num_bytes":664,"mime_essence":"text/plain","charset":null},"blob_id":"0ee84b84c29924b210e3576fe9d1e8632948bedc","location":{"offset_span":{"start":617,"end":660},"source_span":{"start":{"line":16,"column":17},"end":{"line":16,"column":59}}},"capture_group_index":1,"match_content":"secret","snippet":{"before":"E = \"https://testwebsite.com\"\n ","matching":"secret","after":"testing\"\n\n\n"},"rule_name":"Generic Username and Password (unquoted)"}]}

~~~

If the first line is expanded, it looks like this:

~~~
{
    "type": "finding",
    "rule_name": "Generic API Key",
    "match_content": "32ui1ffdasfhu239b4df2ac6609a9919",
    "num_matches": 1,
    "matches": [
        {
            "provenance": [
                {
                    "kind": "file",
                    "path": "./app/schema/config.py"
                },
                {
                    "kind": "git_repo",
                    "repo_path": "./.git",
                    "commit_provenance": {
                        "commit_kind": "first_seen",
                        "commit_metadata": {
                            "commit_id": "0ee84b84c29924b210e3576fe9d1e8632948bedc",
                            "committer_name": "Princess Leia",
                            "committer_email": "leia@test.com",
                            "committer_timestamp": "1685495256 +0000",
                            "author_name": "Princess Leia",
                            "author_email": "leia@test.com",
                            "author_timestamp": "1685495256 +0000",
                            "message": "framework\n"
                        },
                        "blob_path": "app/schema/config.py"
                    }
                }
            ],
            "blob_metadata": {
                "id": "0ee84b84c29924b210e3576fe9d1e8632948bedc",
                "num_bytes": 664,
                "mime_essence": "text/plain",
                "charset": null
            },
            "blob_id": "0ee84b84c29924b210e3576fe9d1e8632948bedc",
            "location": {
                "offset_span": {
                    "start": 617,
                    "end": 660
                },
                "source_span": {
                    "start": {
                        "line": 16,
                        "column": 17
                    },
                    "end": {
                        "line": 16,
                        "column": 59
                    }
                }
            },
            "capture_group_index": 1,
            "match_content": "32ui1ffdasfhu239b4df2ac6609a9919",
            "snippet": {
                "before": "E = \"https://testwebsite.com\"\n ",
                "matching": "API_KEY = \"32ui1ffdasfhu239b4df2ac6609a9919",
                "after": "\"\n\n\n"
            },
            "rule_name": "Generic API Key"
        }
    ]
}
~~~