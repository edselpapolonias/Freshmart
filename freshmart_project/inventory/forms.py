from django import forms
from .models import InventoryItem
from .models import Category
from django.contrib.auth.models import User
from .models import UserProfile

class InventoryItemForm(forms.ModelForm):
    class Meta:
        model = InventoryItem
        fields = ['product_code', 'product_name', 'description', 'price', 'category']
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

class StockForm(forms.Form):
    product = forms.ModelChoiceField(
        queryset=InventoryItem.objects.all(),
        widget=forms.Select(attrs={'class': 'form-control'}),
        label="Select Product"
    )
    quantity = forms.IntegerField(
        min_value=1,
        widget=forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Enter quantity'}),
        label="Quantity"
    )

class UserRegistrationForm(forms.ModelForm):
    first_name = forms.CharField(max_length=30)
    last_name = forms.CharField(max_length=30)
    email = forms.EmailField()
    username = forms.CharField(max_length=30)
    password = forms.CharField(widget=forms.PasswordInput)
    gender = forms.ChoiceField(choices=UserProfile.GENDER_CHOICES)
    role = forms.ChoiceField(choices=UserProfile.ROLE_CHOICES)
    picture = forms.ImageField(required=False)

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'username', 'password']