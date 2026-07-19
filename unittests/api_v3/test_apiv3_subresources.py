"""
Generic notes / tags / files sub-resource tests for API v3 (§4.12, OS5).

Covers the storage support matrix (notes/files: finding/engagement/test; tags: those + product),
note privacy (v2 parity: private notes are returned, not per-user filtered), parent-authorization
inheritance (404 unknown-or-unauthorized parent, 403 write), multipart upload + streamed download
roundtrip, tag replace/append/delete semantics + normalization, the pagination envelope on the
list endpoints, and the MANDATORY constant-query guarantee for the finding notes/tags/files lists.
"""
from __future__ import annotations

from unittest import mock

from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import connection
from django.test.utils import CaptureQueriesContext

from dojo.models import Dojo_User, Engagement, Finding, Product, Test, User
from dojo.notes.models import Notes

from .base import ApiV3TestCase

_NOTE_KEYS = {"id", "entry", "author", "private", "edited", "created", "updated"}
_FILE_KEYS = {"id", "title", "size", "created"}
_ENVELOPE_KEYS = {"count", "next", "previous", "results"}


def _txt(name: str = "os5upload.txt", body: bytes = b"os5 file body") -> SimpleUploadedFile:
    return SimpleUploadedFile(name, body, content_type="text/plain")


class _SubResourceBase(ApiV3TestCase):

    def setUp(self):
        super().setUp()
        self.finding = Finding.objects.first()
        self.engagement = Engagement.objects.first()
        self.test = Test.objects.first()
        self.product = Product.objects.first()
        self.note_file_parents = [
            ("findings", self.finding),
            ("engagements", self.engagement),
            ("tests", self.test),
        ]
        self.tag_parents = [*self.note_file_parents, ("products", self.product)]


class TestApiV3SubresourcesNotes(_SubResourceBase):

    def test_notes_matrix_create_and_list_roundtrip(self):
        for resource, parent in self.note_file_parents:
            with self.subTest(resource=resource):
                created = self.client.post(
                    self.v3_url(f"{resource}/{parent.pk}/notes"),
                    {"entry": f"note on {resource}", "private": False},
                    format="json",
                )
                self.assertEqual(201, created.status_code, created.content[:400])
                body = created.json()
                self.assertEqual(_NOTE_KEYS, set(body))
                self.assertEqual(f"note on {resource}", body["entry"])
                self.assertFalse(body["private"])
                self.assertFalse(body["edited"])
                self.assertEqual(self.admin.pk, body["author"]["id"])
                self.assertEqual("admin", body["author"]["name"])
                self.assertIsNotNone(body["created"])

                listing = self.get_json(f"{resource}/{parent.pk}/notes")
                self.assertEqual(_ENVELOPE_KEYS, set(listing) - {"meta"})
                self.assertIn(body["id"], [n["id"] for n in listing["results"]])
                self.assertEqual(_NOTE_KEYS, set(listing["results"][0]))

    def test_note_created_persisted_and_linked_to_parent(self):
        before = self.finding.notes.count()
        self.client.post(
            self.v3_url(f"findings/{self.finding.pk}/notes"),
            {"entry": "persisted"}, format="json",
        )
        self.assertEqual(before + 1, self.finding.notes.count())

    def test_note_unknown_field_is_400(self):
        response = self.client.post(
            self.v3_url(f"findings/{self.finding.pk}/notes"),
            {"entry": "x", "bogus": 1}, format="json",
        )
        self.assertEqual(400, response.status_code)
        self.assertEqual("application/problem+json", response["Content-Type"])

    def test_note_missing_entry_is_400(self):
        response = self.client.post(
            self.v3_url(f"findings/{self.finding.pk}/notes"), {}, format="json",
        )
        self.assertEqual(400, response.status_code)


class TestApiV3SubresourcesNotePrivacy(_SubResourceBase):

    def test_private_note_returned_and_flagged(self):
        created = self.client.post(
            self.v3_url(f"findings/{self.finding.pk}/notes"),
            {"entry": "secret", "private": True}, format="json",
        ).json()
        self.assertTrue(created["private"])
        listing = self.get_json(f"findings/{self.finding.pk}/notes")
        match = next(n for n in listing["results"] if n["id"] == created["id"])
        self.assertTrue(match["private"])

    def test_private_note_visible_to_other_authorized_user_v2_parity(self):
        """v2 parity: the notes endpoint returns *all* notes; `private` is not a per-user read filter."""
        member = Dojo_User.objects.create_user(username="v3_note_member", password="x")  # noqa: S106
        self.finding.test.engagement.product.authorized_users.add(member)
        created = self.client.post(
            self.v3_url(f"findings/{self.finding.pk}/notes"),
            {"entry": "private-but-visible", "private": True}, format="json",
        ).json()

        member_view = self.get_json(f"findings/{self.finding.pk}/notes", client=self.token_client(user=member))
        self.assertIn(created["id"], [n["id"] for n in member_view["results"]])


class TestApiV3SubresourcesFiles(_SubResourceBase):

    def test_files_matrix_upload_list_download_roundtrip(self):
        for resource, parent in self.note_file_parents:
            with self.subTest(resource=resource):
                body_bytes = f"payload-{resource}".encode()
                created = self.client.post(
                    self.v3_url(f"{resource}/{parent.pk}/files"),
                    {"title": f"os5 {resource} attachment", "file": _txt(body=body_bytes)},
                    format="multipart",
                )
                self.assertEqual(201, created.status_code, created.content[:400])
                fbody = created.json()
                self.assertEqual(_FILE_KEYS, set(fbody))
                self.assertEqual(f"os5 {resource} attachment", fbody["title"])
                self.assertEqual(len(body_bytes), fbody["size"])
                self.assertIsNone(fbody["created"])

                listing = self.get_json(f"{resource}/{parent.pk}/files")
                self.assertEqual(_ENVELOPE_KEYS, set(listing) - {"meta"})
                self.assertIn(fbody["id"], [f["id"] for f in listing["results"]])

                dl = self.client.get(self.v3_url(f"{resource}/{parent.pk}/files/{fbody['id']}/download"))
                self.assertEqual(200, dl.status_code)
                self.assertIn("attachment", dl["Content-Disposition"])
                self.assertEqual(body_bytes, b"".join(dl.streaming_content))

    def test_upload_rejects_disallowed_extension(self):
        response = self.client.post(
            self.v3_url(f"findings/{self.finding.pk}/files"),
            {"title": "os5 evil", "file": _txt(name="evil.exe")},
            format="multipart",
        )
        self.assertEqual(400, response.status_code, response.content[:400])
        self.assertEqual("application/problem+json", response["Content-Type"])
        self.assertIn("file", response.json()["fields"])

    def test_duplicate_title_is_400(self):
        payload = {"title": "os5 dup title", "file": _txt()}
        first = self.client.post(self.v3_url(f"findings/{self.finding.pk}/files"), payload, format="multipart")
        self.assertEqual(201, first.status_code)
        dup = self.client.post(
            self.v3_url(f"tests/{self.test.pk}/files"),
            {"title": "os5 dup title", "file": _txt()}, format="multipart",
        )
        self.assertEqual(400, dup.status_code, dup.content[:400])

    def test_download_missing_file_is_404(self):
        response = self.client.get(self.v3_url(f"findings/{self.finding.pk}/files/9999999/download"))
        self.assertEqual(404, response.status_code)


class TestApiV3SubresourcesTags(_SubResourceBase):

    def test_tags_get_shape_all_resources(self):
        for resource, parent in self.tag_parents:
            with self.subTest(resource=resource):
                body = self.get_json(f"{resource}/{parent.pk}/tags")
                self.assertEqual({"tags"}, set(body))
                self.assertIsInstance(body["tags"], list)

    def test_tags_replace_append_delete_semantics(self):
        # Product tags have clean semantics (no inheritance-sticky re-add); inheritance is off by
        # default anyway, but products are the crispest surface for the exact-set assertions.
        for resource, parent in self.tag_parents:
            with self.subTest(resource=resource):
                base = self.v3_url(f"{resource}/{parent.pk}/tags")
                # PUT replace + normalization (force_lowercase).
                replaced = self.client.put(base, {"tags": ["PCI", "Sox"]}, format="json")
                self.assertEqual(200, replaced.status_code, replaced.content[:400])
                self.assertEqual({"pci", "sox"}, set(replaced.json()["tags"]))
                # POST append (dedup, case-insensitive).
                appended = self.client.post(base, {"tags": ["Extra", "PCI"]}, format="json")
                self.assertEqual(200, appended.status_code)
                self.assertEqual({"pci", "sox", "extra"}, set(appended.json()["tags"]))
                # DELETE one (case-insensitive match on the stored lowercase tag).
                removed = self.client.delete(self.v3_url(f"{resource}/{parent.pk}/tags/PCI"))
                self.assertEqual(204, removed.status_code)
                self.assertEqual({"sox", "extra"}, set(self.get_json(f"{resource}/{parent.pk}/tags")["tags"]))

    def test_delete_absent_tag_is_404(self):
        self.client.put(self.v3_url(f"findings/{self.finding.pk}/tags"), {"tags": ["keep"]}, format="json")
        response = self.client.delete(self.v3_url(f"findings/{self.finding.pk}/tags/nope"))
        self.assertEqual(404, response.status_code)
        self.assertEqual("application/problem+json", response["Content-Type"])

    def test_tags_unknown_body_field_is_400(self):
        response = self.client.put(
            self.v3_url(f"findings/{self.finding.pk}/tags"),
            {"tags": ["a"], "bogus": 1}, format="json",
        )
        self.assertEqual(400, response.status_code)


class TestApiV3SubresourcesSupportMatrix(_SubResourceBase):

    """Sub-resources are attached only where the model stores them; everything else is 404."""

    def test_unsupported_notes_and_files_are_404(self):
        pt_id = self.product.prod_type_id
        for path in (
            f"product_types/{pt_id}/notes",
            f"product_types/{pt_id}/files",
            f"products/{self.product.pk}/notes",   # product has tags but no notes/files
            f"products/{self.product.pk}/files",
            f"users/{self.admin.pk}/notes",
            f"users/{self.admin.pk}/files",
        ):
            with self.subTest(path=path):
                self.assertEqual(404, self.client.get(self.v3_url(path)).status_code)

    def test_unsupported_tags_are_404(self):
        # product_type / user have no TagField; location has one but is read-only + superuser-only
        # with no v2 tag-mutation endpoint, so no tag sub-resource is attached (tags[] is on its
        # read shape instead).
        from dojo.location.models import Location  # noqa: PLC0415
        location = Location.objects.first()
        for path in (
            f"product_types/{self.product.prod_type_id}/tags",
            f"users/{self.admin.pk}/tags",
            *([f"locations/{location.pk}/tags"] if location else []),
        ):
            with self.subTest(path=path):
                self.assertEqual(404, self.client.get(self.v3_url(path)).status_code)


class TestApiV3SubresourcesAuthInheritance(_SubResourceBase):

    """Authorization inherited from the parent: 404 unknown-or-unauthorized parent, 403 on write."""

    def test_unknown_parent_is_404(self):
        for path in (
            "findings/9999999/notes",
            "engagements/9999999/files",
            "tests/9999999/tags",
            "products/9999999/tags",
        ):
            with self.subTest(path=path):
                self.assertEqual(404, self.client.get(self.v3_url(path)).status_code)

    def test_unauthorized_parent_is_404_not_403(self):
        """A non-member cannot see the parent, so every sub-resource op is 404 (never leak existence)."""
        limited = User.objects.create_user(username="v3_sub_limited", password="x")  # noqa: S106
        client = self.token_client(user=limited)
        self.assertEqual(404, client.get(self.v3_url(f"findings/{self.finding.pk}/notes")).status_code)
        self.assertEqual(404, client.get(self.v3_url(f"findings/{self.finding.pk}/files")).status_code)
        self.assertEqual(404, client.get(self.v3_url(f"findings/{self.finding.pk}/tags")).status_code)
        post = client.post(
            self.v3_url(f"findings/{self.finding.pk}/notes"), {"entry": "x"}, format="json",
        )
        self.assertEqual(404, post.status_code)

    def test_write_forbidden_when_permission_fails_is_403(self):
        """
        Parent visible (admin/superuser) but the write permission check fails -> 403. Under the OS
        legacy model a viewing member also has edit/add, so this exercises the 403 code path via a
        permission-check failure (see .claude/os5-report.md / §12).
        """
        with mock.patch("dojo.api_v3.subresources.user_has_permission", return_value=False):
            note = self.client.post(
                self.v3_url(f"findings/{self.finding.pk}/notes"), {"entry": "x"}, format="json",
            )
            self.assertEqual(403, note.status_code, note.content[:300])
            self.assertEqual("application/problem+json", note["Content-Type"])

            tag = self.client.put(
                self.v3_url(f"findings/{self.finding.pk}/tags"), {"tags": ["x"]}, format="json",
            )
            self.assertEqual(403, tag.status_code)

            upload = self.client.post(
                self.v3_url(f"findings/{self.finding.pk}/files"),
                {"title": "os5 403", "file": _txt()}, format="multipart",
            )
            self.assertEqual(403, upload.status_code)


class TestApiV3SubresourcesPagination(_SubResourceBase):

    def test_notes_list_pagination_envelope(self):
        for i in range(5):
            note = Notes.objects.create(entry=f"pag {i}", author=self.admin)
            self.finding.notes.add(note)
        body = self.get_json(f"findings/{self.finding.pk}/notes", data={"limit": 2})
        self.assertGreaterEqual(body["count"], 5)
        self.assertEqual(2, len(body["results"]))
        self.assertIsNotNone(body["next"])
        self.assertIsNone(body["previous"])


class TestApiV3SubresourcesQueryCounts(_SubResourceBase):

    """MANDATORY: finding notes/tags/files list query counts are independent of row count."""

    def _query_count(self, path: str) -> int:
        with CaptureQueriesContext(connection) as ctx:
            response = self.client.get(self.v3_url(path))
            self.assertEqual(200, response.status_code)
        return len(ctx.captured_queries)

    def test_notes_list_query_count_constant(self):
        path = f"findings/{self.finding.pk}/notes?limit=250"
        for i in range(5):
            self.finding.notes.add(Notes.objects.create(entry=f"n{i}", author=self.admin))
        first = self._query_count(path)
        for i in range(50):
            self.finding.notes.add(Notes.objects.create(entry=f"m{i}", author=self.admin))
        self.assertEqual(first, self._query_count(path))

    def test_files_list_query_count_constant(self):
        path = f"findings/{self.finding.pk}/files?limit=250"
        for i in range(5):
            self.finding.files.create(title=f"qc-a-{i}.txt", file=_txt())
        first = self._query_count(path)
        for i in range(50):
            self.finding.files.create(title=f"qc-b-{i}.txt", file=_txt())
        self.assertEqual(first, self._query_count(path))

    def test_tags_list_query_count_constant(self):
        path = f"findings/{self.finding.pk}/tags"
        self.finding.tags.add("t1", "t2", "t3")
        first = self._query_count(path)
        self.finding.tags.add("t4", "t5", "t6", "t7", "t8", "t9", "t10")
        self.assertEqual(first, self._query_count(path))
