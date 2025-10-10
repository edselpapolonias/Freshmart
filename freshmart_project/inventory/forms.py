from django import forms
from .models import InventoryItem
from .models import Category

class InventoryItemForm(forms.ModelForm):
    class Meta:
        model = InventoryItem
        fields = ['product_code', 'product_name', 'description', 'quantity_in_stock', 'price', 'category']
        widgets = {
            'description': forms.TextInput(attrs={
                'placeholder': 'Enter description',
            }),
        }

class CategoryForm(forms.ModelForm):
    class Meta:
        model = Category
        fields = ['category_name', 'description']
        widgets = {
            'category_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter category name'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'placeholder': 'Enter description'}),
        }
