from django.apps import AppConfig
from watson import search as watson

class DojoConfig(AppConfig):
    name = "dojo"

    def ready(self):
        Product = self.get_model("Product")
        Test = self.get_model("Test")
        Finding = self.get_model("Finding")
        watson.register(Product)
        watson.register(Test)
        watson.register(Finding)
