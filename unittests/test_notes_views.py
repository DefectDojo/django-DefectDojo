import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dojo.settings.settings')
import django
django.setup()
from django.test import RequestFactory
from django.contrib.auth.models import User
from dojo.models import Notes, Engagement, Test, Finding, Test_Type, Product, Product_Type
from dojo.notes.views import delete_note
from datetime import datetime
from django.test import RequestFactory
from django.test import TestCase, override_settings
from django.contrib.messages.storage.fallback import FallbackStorage


class DeleteNoteTestCase(TestCase):
    
    def setUp(self):
        # Crear una instancia de RequestFactory
        self.factory = RequestFactory()

        # Crear un usuario para las pruebas
        self.user, _ = User.objects.get_or_create(username='testuser')

        # Crear un objeto de ejemplo para cada página
        target_start = datetime.strptime('2023-05-11', '%Y-%m-%d')

        # Obtener o crear el producto
        product_type, _ = Product_Type.objects.get_or_create(id=3, name='Default Product Type')
        product, _ = Product.objects.get_or_create(id=3, prod_type=product_type)

        self.engagement = Engagement.objects.create(name='Engagement', target_start=target_start, target_end=target_start, product=product)

        # Crear un test de ejemplo
        test_type, _ = Test_Type.objects.get_or_create(name='Default Test Type')
        self.test = Test.objects.create(engagement=self.engagement, test_type=test_type, target_start=target_start, target_end=target_start)

        # Crear una nota de ejemplo
        self.note = Notes.objects.create(author=self.user, entry='Test note')

        # Crear un finding de ejemplo
        self.finding = Finding.objects.create(test=self.test)
        self.finding.reporter = self.user
        self.finding.save()




    def test_delete_note(self):
        request = self.factory.delete('/notes/{}/delete/{}/{}'.format(self.note.id, 'engagement', self.engagement.id))
        request.user = self.user
        request.POST = {'id': self.note.id}

        # Ejecutar la vista de eliminación de nota
        setattr(request, 'session', 'session')
        messages = FallbackStorage(request)
        setattr(request, '_messages', messages)


        response = delete_note(request, self.note.id, 'engagement', self.engagement.id)

        # Agregar mensajes de depuración
        print('Note exists in database:', Notes.objects.filter(id=self.note.id).exists())

        # Verificar que la respuesta sea una redirección
        self.assertEqual(response.status_code, 302)

        # Verificar que la nota haya sido eliminada
        self.assertFalse(Notes.objects.filter(id=self.note.id).exists())

    def test_delete_note_page_test(self):
        request = self.factory.delete('/notes/{}/delete/{}/{}'.format(self.note.id, 'test', self.test.id))
        request.user = self.user
        request.POST = {'id': self.note.id}

        # Ejecutar la vista de eliminación de nota
        setattr(request, 'session', 'session')
        messages = FallbackStorage(request)
        setattr(request, '_messages', messages)

        response = delete_note(request, self.note.id, 'test', self.test.id)

        # Agregar mensajes de depuración
        print('Note exists in database:', Notes.objects.filter(id=self.note.id).exists())

        # Verificar que la respuesta sea una redirección
        self.assertEqual(response.status_code, 302)

        # Verificar que la nota haya sido eliminada
        self.assertFalse(Notes.objects.filter(id=self.note.id).exists())

    def test_delete_note_finding(self):
        request = self.factory.delete('/notes/{}/delete/{}/{}'.format(self.note.id, 'finding', self.finding.id))
        request.user = self.user
        request.POST = {'id': self.note.id}

        # Crear un objeto de ejemplo para la prueba de finding
        self.finding = Finding.objects.create(test=self.test)

        # Ejecutar la vista de eliminación de nota
        setattr(request, 'session', 'session')
        messages = FallbackStorage(request)
        setattr(request, '_messages', messages)

        response = delete_note(request, self.note.id, 'finding', self.finding.id)

        # Agregar mensajes de depuración
        print('Note exists in database:', Notes.objects.filter(id=self.note.id).exists())

        # Verificar que la respuesta sea una redirección
        self.assertEqual(response.status_code, 302)

        # Verificar que la nota haya sido eliminada
        self.assertFalse(Notes.objects.filter(id=self.note.id).exists())