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
    password = forms.CharField(widget=forms.PasswordInput, label="Password")
    gender = forms.ChoiceField(choices=UserProfile.GENDER_CHOICES, label="Gender")
    role = forms.ChoiceField(choices=UserProfile.ROLE_CHOICES, label="Role")
    picture = forms.ImageField(required=False, label="Profile Picture")

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'username', 'password', 'gender', 'role', 'picture']

class UserProfileForm(forms.ModelForm):
    first_name = forms.CharField(max_length=30)
    last_name = forms.CharField(max_length=30)
    email = forms.EmailField()

    class Meta:
        model = UserProfile
        fields = ['picture', 'gender']  # role is excluded so it’s not editable

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        if user:
            self.fields['first_name'].initial = user.first_name
            self.fields['last_name'].initial = user.last_name
            self.fields['email'].initial = user.email

class OTPForm(forms.Form):
    otp = forms.CharField(
        max_length=6, 
        label="Enter OTP", 
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter 6-digit code'})
    )

