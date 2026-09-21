from dojo.tools.locations import LocationData, split_image_reference
from unittests.dojo_test_case import DojoTestCase


class TestSplitImageReference(DojoTestCase):
    def test_splits_registry_repository_tag_and_digest_without_normalising(self):
        digest = "sha256:" + "a" * 64
        cases = {
            "nginx:1.25": {"registry": "", "repository": "nginx", "tag": "1.25", "digest": ""},
            "docker.io/library/nginx:1.25": {"registry": "docker.io", "repository": "library/nginx", "tag": "1.25", "digest": ""},
            "localhost:5000/team/svc:v1": {"registry": "localhost:5000", "repository": "team/svc", "tag": "v1", "digest": ""},
            "registry.example.com:8443/team/svc": {"registry": "registry.example.com:8443", "repository": "team/svc", "tag": "", "digest": ""},
            f"ghcr.io/example/api@{digest}": {"registry": "ghcr.io", "repository": "example/api", "tag": "", "digest": digest},
            f"quay.io/org/app:1.0@{digest}": {"registry": "quay.io", "repository": "org/app", "tag": "1.0", "digest": digest},
            "teamdojo:latest": {"registry": "", "repository": "teamdojo", "tag": "latest", "digest": ""},
        }
        for reference, expected in cases.items():
            with self.subTest(reference=reference):
                self.assertEqual(expected, split_image_reference(reference))

    def test_empty_reference_is_empty(self):
        self.assertEqual({}, split_image_reference(""))
        self.assertEqual({}, split_image_reference("   "))

    def test_image_factory_emits_exactly_six_keys(self):
        location = LocationData.image(registry="ghcr.io", repository="example/api", tag="1.0")
        self.assertEqual("image", location.type)
        self.assertEqual(
            {"registry": "ghcr.io", "repository": "example/api", "digest": "", "tag": "1.0", "oci_source": "", "oci_revision": ""},
            location.data,
        )
