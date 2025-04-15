from django.apps import AppConfig
"""from django.apps import signals
"""

class MyappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'myapp'

    def ready(self):
        import myapp.signals  # Ensure signals are loaded
