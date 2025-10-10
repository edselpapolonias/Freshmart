from django.shortcuts import render, get_object_or_404, redirect
from .models import InventoryItem, StockHistory
from .forms import InventoryItemForm
from django.shortcuts import render
from .forms import CategoryForm 
from .models import Category
from .forms import StockForm
from django.db.models import Sum, F
from django.contrib import messages
from django.db.models.functions import Lower
from django.shortcuts import render
from django.db.models.functions import TruncDate
from .models import UserProfile
from .forms import UserRegistrationForm
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from functools import wraps
from django.contrib.auth import logout
from django.views.decorators.cache import never_cache
from django.http import JsonResponse



@login_required
def product_manage(request, pk=None):
    if pk:  # For edit mode
        item = get_object_or_404(InventoryItem, pk=pk)
        edit_mode = True
    else:
        item = None
        edit_mode = False

    # Handle form submission
    if request.method == 'POST':
        if 'delete' in request.POST:
            # Handle delete directly
            if item:
                item.delete()
            return redirect('product_manage')

        form = InventoryItemForm(request.POST, instance=item)
        if form.is_valid():
            form.save()
            return redirect('product_manage')
    else:
        form = InventoryItemForm(instance=item)

    # Fetch all products
    items = InventoryItem.objects.all()

    return render(request, 'inventory/manage_product.html', {
        'form': form,
        'items': items,
        'edit_mode': edit_mode,
    })

def index(request):
    return render(request, 'index.html')

def category_list_add(request):
    if request.method == 'POST':
        form = CategoryForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('category_list_add') 
    else:
        form = CategoryForm()

    categories = Category.objects.all()

    return render(request, 'inventory/add_category.html', {
        'form': form,
        'categories': categories
    })

def category_edit(request, pk):
    category = get_object_or_404(Category, pk=pk)
    if request.method == 'POST':
        form = CategoryForm(request.POST, instance=category)
        if form.is_valid():
            form.save()
            return redirect('category_list_add')
    else:
        form = CategoryForm(instance=category)
    
    categories = Category.objects.all()
    return render(request, 'inventory/add_category.html', {
        'form': form,
        'categories': categories,
        'edit_mode': True,
        'category_id': pk
    })

def category_delete(request, pk):
    category = get_object_or_404(Category, pk=pk)
    category.delete()
    return redirect('category_list_add')

def product_detail(request, pk):
    product = get_object_or_404(InventoryItem, pk=pk)
    return render(request, 'inventory/product_detail.html', {
        'product': product
    })

def stock_management(request):
    if request.method == 'POST':
        form = StockForm(request.POST)
        if form.is_valid():
            product = form.cleaned_data['product']
            quantity = form.cleaned_data['quantity']

            if 'add_stock' in request.POST:
                product.quantity_in_stock += quantity
            elif 'deduct_stock' in request.POST:
                product.quantity_in_stock -= quantity
                if product.quantity_in_stock < 0:
                    product.quantity_in_stock = 0  # Prevent negative stock

            product.save()
            return redirect('stock_management')
    else:
        form = StockForm()

    products = InventoryItem.objects.all()
    return render(request, 'inventory/stock_management.html', {
        'form': form,
        'products': products
    })

def stock_management(request):
    if request.method == 'POST':
        form = StockForm(request.POST)
        if form.is_valid():
            product = form.cleaned_data['product']
            quantity = form.cleaned_data['quantity']

            old_quantity = product.quantity_in_stock

            if 'add_stock' in request.POST:
                product.quantity_in_stock += quantity
                action = 'ADD'
                product.save()

                # Save stock history
                StockHistory.objects.create(
                    product=product,
                    old_quantity=old_quantity,
                    input_quantity=quantity,
                    new_quantity=product.quantity_in_stock,
                    action=action
                )
                messages.success(request, f"{quantity} added to {product.product_name} stock.")

            elif 'deduct_stock' in request.POST:
                if quantity > product.quantity_in_stock:
                    messages.error(request, f"Cannot deduct {quantity} from {product.product_name}. Only {product.quantity_in_stock} in stock.")
                else:
                    product.quantity_in_stock -= quantity
                    action = 'DEDUCT'
                    product.save()

                    # Save stock history
                    StockHistory.objects.create(
                        product=product,
                        old_quantity=old_quantity,
                        input_quantity=quantity,
                        new_quantity=product.quantity_in_stock,
                        action=action
                    )
                    messages.success(request, f"{quantity} deducted from {product.product_name} stock.")

            return redirect('stock_management')
    else:
        form = StockForm()

    products = InventoryItem.objects.all()
    return render(request, 'inventory/stock_management.html', {
        'form': form,
        'products': products
    })

def stock_history(request):
    history = StockHistory.objects.select_related('product').order_by('-date')
    return render(request, 'inventory/stock_history.html', {'history': history})

def dashboard(request):
    total_products = InventoryItem.objects.count()
    total_value = InventoryItem.objects.aggregate(total=Sum(F('quantity_in_stock') * F('price')))['total'] or 0
    low_stock = InventoryItem.objects.filter(quantity_in_stock__gte=1, quantity_in_stock__lte=20).count()
    out_of_stock = InventoryItem.objects.filter(quantity_in_stock=0).count()
    products_list = InventoryItem.objects.all().order_by('quantity_in_stock')

    context = {
        'total_products': total_products,
        'total_value': total_value,
        'low_stock': low_stock,
        'out_of_stock': out_of_stock,
        'products_list': products_list,
    }
    return render(request, 'index.html', context)

def register(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST, request.FILES)
        if form.is_valid():
            # Create user but do not activate if Admin
            user = form.save(commit=False)
            password = form.cleaned_data.get('password')
            user.set_password(password)

            role = form.cleaned_data.get('role')

            if role == 'Admin':
                user.is_active = False  # Admin cannot log in until approved
            else:
                user.is_active = True  # Regular users can log in immediately

            user.save()

            # Create UserProfile
            profile = UserProfile(
                user=user,
                gender=form.cleaned_data.get('gender'),
                role=role,
                picture=form.cleaned_data.get('picture'),
                is_verified=(role != 'Admin')  # Only regular users are auto-verified
            )
            profile.save()

            # Admin-specific message
            if role == 'Admin':
                messages.info(request, 'Your admin account is pending verification by the system administrator.')
                return redirect('waiting_verification')
            else:
                messages.success(request, 'Account created successfully! You can now log in.')
                return redirect('login')
    else:
        form = UserRegistrationForm()
    return render(request, 'registration/register.html', {'form': form})

def unverified_admin_or_superuser_required(view_func):
    """Decorator to restrict access to Admins (verified or not) OR Superusers."""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        # 1. Check if the user is a Superuser (bypasses all other checks)
        if request.user.is_authenticated and request.user.is_superuser:
            return view_func(request, *args, **kwargs)

        # 2. Check for ANY admin role (verified or unverified)
        is_any_admin = (
            request.user.is_authenticated and 
            hasattr(request.user, 'userprofile') and 
            request.user.userprofile.role == 'Admin'
        )

        if is_any_admin:
            # If they are an unverified admin, they can access the verification page/actions
            return view_func(request, *args, **kwargs)
        
        # 3. Deny access if not an admin or superuser
        return HttpResponseForbidden("You do not have permission to access this page.")
    return wrapper

def admin_required(view_func):
    """Decorator to restrict access to VERIFIED Admin users OR Superusers."""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        # 1. Check if the user is a Superuser (bypasses all other checks)
        if request.user.is_authenticated and request.user.is_superuser:
            return view_func(request, *args, **kwargs)

        # 2. Check for a regular verified admin
        is_admin_verified = (
            request.user.is_authenticated and 
            hasattr(request.user, 'userprofile') and 
            request.user.userprofile.role == 'Admin' and 
            request.user.userprofile.is_verified
        )

        if is_admin_verified:
            return view_func(request, *args, **kwargs)
        
        # 3. Handle pending/unauthorized admins: Redirect UNVERIFIED admins to the waiting page
        if request.user.is_authenticated and hasattr(request.user, 'userprofile') and request.user.userprofile.role == 'Admin' and not request.user.userprofile.is_verified:
             return redirect('waiting_verification') 
        
        return HttpResponseForbidden("You do not have permission to access this page.")
    return wrapper


def user_list(request):
    users = UserProfile.objects.select_related('user').all()
    return render(request, 'inventory/user_list.html', {'users': users})

def logout_view(request):
    logout(request)  # Ends the user session
    response = redirect('login')
    # Add no-cache headers to the redirect response
    response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response['Pragma'] = 'no-cache'
    response['Expires'] = '0'
    return response


@login_required
@unverified_admin_or_superuser_required # Allows unverified admins and superusers
def admin_verification(request):
    # Logic is correct, as the decorator handles the access check.
    if not hasattr(request.user, 'userprofile') and not request.user.is_superuser:
        return HttpResponseForbidden("Invalid user profile setup.")

    pending_admins = UserProfile.objects.filter(role='Admin', is_verified=False).exclude(user=request.user)
    
    return render(request, 'admin_verification.html', {'pending_admins': pending_admins})



@login_required
@unverified_admin_or_superuser_required # Allows unverified admins and superusers
def approve_admin(request, profile_id):
    profile = get_object_or_404(UserProfile, id=profile_id)
    
    if request.method == 'POST':
        profile.is_verified = True
        profile.user.is_active = True # IMPORTANT: Active lets them log in now
        profile.user.save()
        profile.save()
        message = f"{profile.user.username}'s admin account has been approved."

        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JsonResponse({'success': True, 'message': message})
        else:
            messages.success(request, message)
            return redirect('admin_verification')

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        return JsonResponse({'success': False, 'message': 'Invalid request method or permission denied.'})
    else:
        return HttpResponseForbidden("You do not have permission to access this page.")



@login_required
@unverified_admin_or_superuser_required # Allows unverified admins and superusers
def decline_admin(request, profile_id):
    profile = get_object_or_404(UserProfile, id=profile_id)
    
    if request.method == 'POST':
        username = profile.user.username
        profile.user.delete() # Deletes user and cascades to profile
        
        message = f"{username}'s admin account has been declined and removed."

        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JsonResponse({'success': True, 'message': message})
        else:
            messages.error(request, message)
            return redirect('admin_verification')

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        return JsonResponse({'success': False, 'message': 'Invalid request method or permission denied.'})
    else:
        return HttpResponseForbidden("You do not have permission to access this page.")



def waiting_verification(request):
    return render(request, 'waiting_verification.html')

def declined_verification(request):
    return render(request, 'declined_verification.html')
