from django.contrib import admin
from django.urls import path, include
from django.http import JsonResponse
from django.conf import settings
from django.conf.urls.static import static

def home(request):
    return JsonResponse({"message": "Welcome to the Employee API! Use /api/employees/ to get all data.or use /api/employees/id for filter based on emp_id "})


urlpatterns = [
    path('', home), 
    path('admin/', admin.site.urls),
    path('api/', include('myapp.urls')),   
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)