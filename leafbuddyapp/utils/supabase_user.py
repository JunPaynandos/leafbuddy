from django.contrib.auth.models import AbstractBaseUser

class SupabaseUser:
    def __init__(self, user_dict):
        self.id = user_dict["id"]
        self.email = user_dict["email"]
        self.password = user_dict.get("password") or ""
        self.last_login = user_dict.get("last_login")
        self.is_active = user_dict.get("is_active", False)

    def get_username(self):
        return self.email
    
    def get_email_field_name(self):
        return "email"

    @property
    def pk(self):
        return self.id
