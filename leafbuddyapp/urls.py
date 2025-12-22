from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', views.home, name='home'),
    path('scan', views.scan, name='scan'),
    path('library', views.library, name='library'),
    path('about', views.about, name='about'),
    path('contact', views.contact, name='contact'),
    path('login/', views.login, name='login'),
    path('signup/', views.signup, name='signup'),
    path("result/", views.result, name="result"),
    path("api/predict-frame/", views.predict_frame, name="predict_frame"),
    path('set-password/', views.set_password_view, name='set_password'),
    path('auth/callback/', views.auth_callback, name='auth_callback'),
    path('logout/', views.logout, name='logout'),
    path("library/<str:crop_name>/", views.crop_diseases, name="crop_diseases"),
    path("library/<str:crop_name>/<str:disease_name>/", views.disease_detail, name="disease_detail"),
    path("settings/", views.settings_view, name="settings"),
    path("history/", views.analysis_history, name="history"),
    path('history/delete/<int:id>/', views.delete_history, name='delete_history'),
    path("delete-account/", views.delete_account, name="delete_account"),
    path('auth/confirm-email/<uidb64>/<token>/', views.confirm_email, name='confirm_email'),
    path("auth/resend-confirmation-email/", views.resend_confirmation_email, name="resend_confirmation_email"),
    path("forgot-password/", views.forgot_password, name="forgot_password"),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)