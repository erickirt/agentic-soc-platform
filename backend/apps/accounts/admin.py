from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import User


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    list_display = (
        "username",
        "email",
        "mobile_phone",
        "auth_type",
        "is_active",
    )
    fieldsets = UserAdmin.fieldsets + (
        ("Extra", {"fields": ("mobile_phone", "auth_type")}),
    )
