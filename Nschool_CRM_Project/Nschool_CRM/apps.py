from django.apps import AppConfig


class NschoolCrmConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'Nschool_CRM'
    
    def ready(self):
        import Nschool_CRM.signals 
