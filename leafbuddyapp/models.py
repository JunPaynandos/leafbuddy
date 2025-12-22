from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
import uuid

# Custom manager for the User model
class CustomUserManager(BaseUserManager):
    def create_user(self, email, username, first_name, last_name, password=None):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, first_name=first_name, last_name=last_name)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, first_name, last_name, password=None):
        user = self.create_user(email, username, first_name, last_name, password)
        user.is_active = True
        user.is_superuser = True
        user.save(using=self._db)
        return user

# Custom User Model
class User(AbstractBaseUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    username = models.CharField(max_length=255, unique=True)
    email = models.EmailField(unique=True)
    profile_image = models.TextField(null=True, blank=True)  # Store URL of the image
    password = models.CharField(max_length=255, null=True, blank=True)
    role = models.CharField(max_length=20, default='user')
    auth_provider = models.CharField(max_length=50, default='email')
    is_active = models.BooleanField(default=False)
    email_verified = models.BooleanField(default=False)
    email_verification_token = models.CharField(max_length=255, null=True, blank=True)
    email_verification_token_expiry = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login = models.DateTimeField(null=True, blank=True)
    last_confirmation_email_sent = models.DateTimeField(null=True, blank=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'first_name', 'last_name']

    objects = CustomUserManager()

    class Meta:
        db_table = 'users'

    def __str__(self):
        return self.email

class Crop(models.Model):
    name = models.CharField(max_length=50, unique=True)
    model_type = models.CharField(max_length=10, choices=[("keras", "Keras"), ("pytorch", "PyTorch")])
    model_file = models.CharField(max_length=255)
    label_file = models.CharField(max_length=255)

    def __str__(self):
        return self.name.capitalize()

class AnalysisHistory(models.Model):
    user_id = models.CharField(max_length=50) 
    crop = models.ForeignKey(Crop, on_delete=models.CASCADE)
    image_url = models.URLField(null=True, blank=True)
    predicted_class = models.CharField(max_length=100)
    confidence = models.FloatField(null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    symptoms = models.TextField(null=True, blank=True)
    treatment = models.TextField(null=True, blank=True)
    prevention = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
