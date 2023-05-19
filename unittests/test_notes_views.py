import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dojo.settings.settings')
import django
django.setup()
import unittest
from django.test import RequestFactory
from django.contrib.auth.models import User
from dojo.models import Notes, Engagement, Test, Finding, Test_Type, Product, Product_Type
from dojo.notes.views import delete_note
from datetime import datetime
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory
from django.contrib.messages.middleware import MessageMiddleware
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import TestCase, override_settings
from django.test.utils import modify_settings
from django.core.handlers.base import BaseHandler
from django.test import TestCase, override_settings



class DeleteNoteTestCase(TestCase):
    
    def setUp(self):
        # Crear una instancia de RequestFactory
        self.factory = RequestFactory()

        # Crear un usuario para las pruebas
        self.user, _ = User.objects.get_or_create(username='testuser')

        # Crear un objeto de ejemplo para cada página
        target_start = datetime.strptime('2023-05-11', '%Y-%m-%d')

        # Obtener o crear el producto
        #product_type, _ = Product_Type.objects.get_or_create(id=1, defaults={'name': 'Default Product Type'})
        product_type, _ = Product_Type.objects.get_or_create(id=3, name= 'Default Product Type')
        product, _ = Product.objects.get_or_create(id=3, prod_type=product_type)


        self.engagement = Engagement.objects.create(name='Engagement', target_start=target_start, target_end=target_start, product=product)
        test_type_instance, _ = Test_Type.objects.get_or_create(name='Your Test Type')
        self.test = Test.objects.create(engagement=self.engagement, test_type=test_type_instance, target_start=target_start, target_end=target_start)
        self.finding = Finding.objects.create(title='Finding', test=self.test)

        # Crear una nota de ejemplo
        self.note = Notes.objects.create(author=self.user, entry='Test note')

        # Configurar el middleware de mensajes
        handler = BaseHandler()
        self.middleware = MessageMiddleware(handler)

        # Configurar el middleware de sesiones (si es necesario)
        self.session_middleware = SessionMiddleware(handler)

        # Configurar el middleware de mensajes
        self.middleware = MessageMiddleware(handler)

        # Configurar el middleware de sesiones (si es necesario)
        self.session_middleware = SessionMiddleware(handler)


    @override_settings(MIDDLEWARE=[
         # ...
        'django.contrib.sessions.middleware.SessionMiddleware',
        'django.contrib.messages.middleware.MessageMiddleware',
        # ...
    ])
    def test_delete_note(self):
        # Crear una solicitud DELETE para eliminar una nota de un compromiso
        request = self.factory.delete('/delete_note/1/engagement/1/')
        request.user = self.user

        """# Ejecutar la vista de eliminación de nota
        response = delete_note(request, self.note.id, 'engagement', self.engagement.id)


        # Verificar que la respuesta sea una redirección
        self.assertEqual(response.status_code, 302)

        # Verificar que la nota haya sido eliminada
        self.assertFalse(Notes.objects.filter(id=self.note.id).exists())
"""

