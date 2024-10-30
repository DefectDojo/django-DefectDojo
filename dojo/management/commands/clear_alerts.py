from django.core.management.base import BaseCommand

from dojo.models import Alerts, Dojo_User

"""
Author: Cody Maffucci
This script will remove all alerts in a few different ways
all: Remove all alerts from the database
user: Clear alerts for a given user
system: Clear system alert
"""


class Command(BaseCommand):
    help = "Remove alerts from the database"

    def add_arguments(self, parser):
        parser.add_argument("-a", "--all", action="store_true", help="Remove all alerts from the database")
        parser.add_argument("-s", "--system", action="store_true", help="Remove alerts wihtout a user")
        parser.add_argument("-u", "--users", nargs="+", type=str, help="Removes alerts from users")

    def handle(self, *args, **options):
        alls = options["all"]
        users = options["users"]
        system = options["system"]

        if users:
            for user_name in users:
                try:
                    user = Dojo_User.objects.get(username=user_name)
                    Alerts.objects.filter(user_id_id=user.id).delete()
                    self.stdout.write(f'User Alerts for "{user_name}" deleted with success!')
                except:
                    self.stdout.write(f'User "{user_name}" does not exist.')
        elif alls and not system:
            Alerts.objects.all().delete()
        elif system and not alls:
            Alerts.objects.filter(user_id_id=None).delete()
        else:
            self.stdout.write("Input is confusing...")
