from django.contrib import admin
from .models import Employee, Products, User, UserProfile,OrderItem, Order
from django.contrib.auth.admin import UserAdmin

# Register your models here.
admin.site.register(Employee)
admin.site.register(Products)
"""admin.site.register(User,UserAdmin)"""
admin.site.register(UserProfile)
admin.site.register(Order)
admin.site.register(OrderItem)




