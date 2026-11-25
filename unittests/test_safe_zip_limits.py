import io
import zipfile

from django.conf import settings
from django.test import SimpleTestCase, override_settings

from dojo.tools.utils import safe_open_zip

MB = 1024 * 1024


def _zip_of_zeros(*member_sizes: int) -> io.BytesIO:
    """A deflated zip whose members hold the given number of zero bytes, written in chunks."""
    buffer = io.BytesIO()
    chunk = bytes(MB)
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for index, size in enumerate(member_sizes):
            with archive.open(f"member-{index}.json", "w", force_zip64=True) as member:
                for _ in range(size // MB):
                    member.write(chunk)
                member.write(bytes(size % MB))
    buffer.seek(0)
    return buffer


class TestSafeZipDefaultLimits(SimpleTestCase):
    def test_default_limits(self):
        self.assertEqual(settings.MAX_ZIP_MEMBERS, 1000)
        self.assertEqual(settings.MAX_ZIP_MEMBER_SIZE, 128 * MB)
        self.assertEqual(settings.MAX_ZIP_TOTAL_SIZE, 128 * MB)
        self.assertEqual(settings.MAX_ZIP_RATIO, 100)

    @override_settings(MAX_ZIP_RATIO=10**6)
    def test_member_over_128_mb_is_refused(self):
        with self.assertRaisesRegex(ValueError, "exceeding the per-member limit of 134217728 bytes"):
            safe_open_zip(_zip_of_zeros(128 * MB + 1))

    @override_settings(MAX_ZIP_RATIO=10**6)
    def test_members_totalling_over_128_mb_are_refused(self):
        with self.assertRaisesRegex(ValueError, "total uncompressed size exceeds the limit of 134217728 bytes"):
            safe_open_zip(_zip_of_zeros(64 * MB, 64 * MB + 1))

    @override_settings(MAX_ZIP_RATIO=10**6)
    def test_members_totalling_128_mb_are_accepted(self):
        with safe_open_zip(_zip_of_zeros(64 * MB, 64 * MB)) as archive:
            self.assertEqual(len(archive.infolist()), 2)
