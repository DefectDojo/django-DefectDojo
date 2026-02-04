from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from dojo.user.authentication import reset_token_for_user


class Command(BaseCommand):
    help = "Rotate (reset) the DRF API token for a target user. Requires an acting user (superuser or global owner)."

    def add_arguments(self, parser):
        parser.add_argument("--acting-user", required=True, help="Username of the acting user performing the reset.")
        parser.add_argument("--username", help="Username of the target user.")
        parser.add_argument("--user-id", type=int, help="ID of the target user.")

    def handle(self, *args, **options):
        User = get_user_model()

        acting_username = options["acting_user"]
        target_username = options.get("username")
        target_user_id = options.get("user_id")

        if bool(target_username) == bool(target_user_id):
            msg = "Provide exactly one of --username or --user-id."
            raise CommandError(msg)

        try:
            acting_user = User.objects.get(username=acting_username)
        except User.DoesNotExist as exc:
            msg = f"Acting user '{acting_username}' does not exist."
            raise CommandError(msg) from exc

        try:
            if target_username:
                target_user = User.objects.get(username=target_username)
            else:
                target_user = User.objects.get(id=target_user_id)
        except User.DoesNotExist as exc:
            msg = "Target user does not exist."
            raise CommandError(msg) from exc

        try:
            reset_token_for_user(acting_user=acting_user, target_user=target_user)
        except Exception as exc:
            raise CommandError(str(exc)) from exc

        self.stdout.write(self.style.SUCCESS("API token reset successfully."))
