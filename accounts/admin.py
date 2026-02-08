from django.contrib import admin

from accounts.models import User,LoginHistory

admin.site.register(User)
admin.site.register(LoginHistory)