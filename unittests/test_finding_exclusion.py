# Dojo
from dojo.models import Dojo_User, Notifications, Finding
from dojo.engine_tools.models import FindingExclusion, FindingExclusionDiscussion
from .dojo_test_case import DojoTestCase

# Utils
from django.utils import timezone
from datetime import timedelta
from django.urls import reverse


class TestFindingExclusion(DojoTestCase):
    def setUp(self):
        self.user = Dojo_User.objects.create_user(username='testuser')
        
        self.exclusion1 = FindingExclusion.objects.create(
            unique_id_from_tool='CVE-2023-1234',
            created_by=self.user,
            status='Pending',
            reason='False positive',
            expiration_date=timezone.now() + timedelta(days=30)
        )
        
        self.exclusion2 = FindingExclusion.objects.create(
            unique_id_from_tool='CVE-2023-5678',
            created_by=self.user,
            status='Accepted',
            reason='Duplicate finding',
            expiration_date=timezone.now() + timedelta(days=60)
        )

    def test_finding_exclusion_creation(self):
        self.assertEqual(FindingExclusion.objects.count(), 2)
        
        self.assertEqual(self.exclusion1.status, 'Pending')
        self.assertEqual(self.exclusion1.unique_id_from_tool, 'CVE-2023-1234')
        self.assertEqual(self.exclusion1.created_by, self.user)

    def test_finding_exclusion_status_workflow(self):
        exclusion = self.exclusion1
        
        self.assertEqual(exclusion.status, 'Pending')
        
        exclusion.status = 'Accepted'
        exclusion.save()
        
        updated_exclusion = FindingExclusion.objects.get(pk=exclusion.pk)
        self.assertEqual(updated_exclusion.status, 'Accepted')

    def test_finding_exclusion_discussion(self):
        discussion = FindingExclusionDiscussion.objects.create(
            finding_exclusion=self.exclusion1,
            author=self.user,
            content='This is a test discussion about the finding exclusion'
        )
        
        self.assertEqual(self.exclusion1.discussions.count(), 1)
        self.assertEqual(discussion.author, self.user)
        self.assertEqual(discussion.content, 'This is a test discussion about the finding exclusion')

    def test_finding_exclusion_status_choices(self):
        valid_statuses = ['Accepted', 'Pending', 'Reviewed', 'Rejected']
        
        for status_choice in valid_statuses:
            exclusion = FindingExclusion.objects.create(
                unique_id_from_tool='TEST-' + status_choice,
                created_by=self.user,
                status=status_choice,
                expiration_date=timezone.now() + timedelta(days=30)
            )
            self.assertIn(exclusion.status, valid_statuses)

    def test_finding_exclusion_expiration(self):
        now = timezone.now()
        future_date = now + timedelta(days=30)
        
        exclusion = FindingExclusion.objects.create(
            unique_id_from_tool='EXPIRATION-TEST',
            created_by=self.user,
            status='Pending',
            expiration_date=future_date
        )
        
        self.assertGreater(exclusion.expiration_date, now)
        self.assertEqual(exclusion.expiration_date, future_date)
            

class FindingExclusionViewsTestCase(DojoTestCase):
    def setUp(self):
        # Crear un usuario de prueba
        self.user = Dojo_User.objects.create_superuser(
            username='testuser', 
            password='12345'
        )
        
        self.exclusion1 = FindingExclusion.objects.create(
            unique_id_from_tool='CVE-2023-1234',
            created_by=self.user,
            status='Pending',
            expiration_date=timezone.now() + timedelta(days=30)
        )
        
        self.exclusion2 = FindingExclusion.objects.create(
            unique_id_from_tool='CVE-2023-5678',
            created_by=self.user,
            status='Accepted',
            expiration_date=timezone.now() + timedelta(days=60)
        )

    def test_finding_exclusion_list_view(self):
        self.client.login(username='testuser', password='12345')
        
        response = self.client.get(reverse('finding_exclusions'))
        
        self.assertEqual(response.status_code, 200)
        
        self.assertIn('exclusions', response.context)
        self.assertIn('filtered', response.context)
        
        self.assertContains(response, 'CVE-2023-1234')
        self.assertContains(response, 'CVE-2023-5678')

    def test_create_finding_exclusion_view(self):
        self.client.login(username='testuser', password='12345')
        
        new_exclusion_data = {
            'unique_id_from_tool': 'CVE-2024-1111',
            'status': 'Pending',
            'reason': 'Test exclusion',
            'expiration_date': timezone.now() + timedelta(days=30)
        }
        
        response = self.client.post(reverse('create_finding_exclusion'), data=new_exclusion_data)
        
        self.assertContains(response, 'CVE-2024-1111')

    def test_show_finding_exclusion_view(self):
        self.client.login(username='testuser', password='12345')
        
        response = self.client.get(reverse('finding_exclusion', args=[str(self.exclusion1.uuid)]))
        
        self.assertEqual(response.status_code, 200)
        
        self.assertIn('finding_exclusion', response.context)
        self.assertEqual(response.context['finding_exclusion'], self.exclusion1)
        
        self.assertContains(response, 'CVE-2023-1234')
        self.assertContains(response, 'Pending')

    def test_add_finding_exclusion_discussion(self):
        self.client.login(username='testuser', password='12345')
        
        discussion_data = {
            'content': 'This is a test discussion'
        }
        
        response = self.client.post(
            reverse('add_finding_exclusion_discussion', args=[str(self.exclusion1.uuid)]), 
            data=discussion_data
        )
        
        self.assertRedirects(response, reverse('finding_exclusion', args=[str(self.exclusion1.uuid)]))
        
        self.assertTrue(
            FindingExclusionDiscussion.objects.filter(
                finding_exclusion=self.exclusion1,
                content='This is a test discussion'
            ).exists()
        )

    def test_unauthorized_access(self):
        client_not_logged = self.client
        
        views_to_test = [
            ('finding_exclusions', None),
            ('create_finding_exclusion', None),
            ('finding_exclusion', [str(self.exclusion1.uuid)]),
            ('add_finding_exclusion_discussion', [str(self.exclusion1.uuid)])
        ]
        
        for view_name, args in views_to_test:
            view_args = args if args else []
            
            response = client_not_logged.get(reverse(view_name, args=view_args))
            
            self.assertEqual(response.status_code, 302)
            self.assertTrue(response.url.startswith(reverse('login')))
            
    def test_accept_finding_exclusion_request(self):
        self.client.login(username='testuser', password='12345')
        
        self.exclusion1.status = 'Pending'
        self.exclusion1.save()
        
        response = self.client.post(
            reverse('accept_finding_exclusion_request', args=[str(self.exclusion1.uuid)])
        )
        
        self.assertRedirects(response, reverse('finding_exclusion', args=[str(self.exclusion1.uuid)]))
        
        updated_exclusion = FindingExclusion.objects.get(uuid=self.exclusion1.uuid)
        
        self.assertEqual(updated_exclusion.status, 'Accepted')
        self.assertEqual(updated_exclusion.final_status, 'Accepted')
        
        findings = Finding.objects.filter(cve=self.exclusion1.unique_id_from_tool)
        for finding in findings:
            self.assertIn('white_list', finding.tags)

    def test_reject_finding_exclusion_request(self):
        self.client.login(username='testuser', password='12345')
        
        self.exclusion1.status = 'Pending'
        self.exclusion1.save()
        
        response = self.client.post(
            reverse('reject_finding_exclusion_request', args=[str(self.exclusion1.uuid)])
        )
        
        self.assertRedirects(response, reverse('finding_exclusion', args=[str(self.exclusion1.uuid)]))
        
        updated_exclusion = FindingExclusion.objects.get(uuid=self.exclusion1.uuid)
        
        self.assertEqual(updated_exclusion.status, 'Rejected')
        self.assertEqual(updated_exclusion.final_status, 'Rejected')

    def test_get_request_redirects(self):
        self.client.login(username='testuser', password='12345')
        
        views_to_test = [
            ('accept_finding_exclusion_request', [str(self.exclusion1.uuid)]),
            ('reject_finding_exclusion_request', [str(self.exclusion1.uuid)])
        ]
        
        for view_name, args in views_to_test:
            response = self.client.get(reverse(view_name, args=args))
            
            self.assertRedirects(response, reverse('finding_exclusion', args=args))