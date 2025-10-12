from django.contrib import admin
from .models import InventoryItem, Category, ProductHistory 

admin.site.register(InventoryItem)
admin.site.register(Category)
admin.site.register(ProductHistory)

