from django.core.management.base import BaseCommand
from dojo.tools.tool_issue_updater import update_findings_from_source_issues

class Command(BaseCommand):
    help = 'Manually trigger update_findings_from_source_issues'

    def handle(self, *args, **options):
        self.stdout.write('Starting update_findings_from_source_issues...')
        update_findings_from_source_issues()
        self.stdout.write(self.style.SUCCESS('Successfully triggered update_findings_from_source_issues'))

# Call this method using:
# docker compose exec uwsgi ./manage.py update_source_issues