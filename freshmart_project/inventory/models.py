from django.db import models
from django.contrib.auth.models import User

class Category(models.Model):
    category_name = models.CharField(max_length=100)
    description = models.TextField(blank=True)

    def __str__(self):
        return self.category_name

class InventoryItem(models.Model):
    product_name = models.CharField(max_length=100)
    product_code = models.CharField(max_length=50)
    description = models.TextField(blank=True)
    quantity_in_stock = models.IntegerField(default=0)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.product_name

class StockHistory(models.Model):
    ACTION_CHOICES = (
        ('ADD', 'Added'),
        ('DEDUCT', 'Deducted'),
    )

    product = models.ForeignKey('InventoryItem', on_delete=models.CASCADE)
    old_quantity = models.IntegerField()
    input_quantity = models.IntegerField()
    new_quantity = models.IntegerField()
    action = models.CharField(max_length=6, choices=ACTION_CHOICES)
    date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.product.product_name} - {self.action} {self.input_quantity}"
    
class UserProfile(models.Model):
    GENDER_CHOICES = (
        ('M', 'Male'),
        ('F', 'Female'),
        ('O', 'Other'),
    )
    ROLE_CHOICES = (
        ('Admin', 'Admin'),
        ('Regular', 'Regular User'),
    )

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES)
    picture = models.ImageField(upload_to='profile_pics/', blank=True, null=True)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='Regular')
    is_verified = models.BooleanField(default=False) 
    is_declined = models.BooleanField(default=False)

    def __str__(self):
        return self.user.username

class ProductHistory(models.Model):
    ACTION_CHOICES = [
        ('Added', 'Added'),
        ('Updated', 'Updated'),
        ('Deleted', 'Deleted'),
    ]
    product = models.ForeignKey('InventoryItem', on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    description = models.TextField()
    date = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return f"{self.action} - {self.product.product_name if self.product else 'Unknown'}"