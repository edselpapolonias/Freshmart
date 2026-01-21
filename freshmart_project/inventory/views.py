from django.shortcuts import render, get_object_or_404, redirect
from .models import InventoryItem, StockHistory
from .forms import InventoryItemForm
from .forms import CategoryForm 
from .models import Category
from .forms import StockForm
from django.db.models import Sum, F, Count
from django.contrib import messages
from django.db.models.functions import Lower
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
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import AuthenticationForm
from django.db import models
from django.utils.timezone import make_aware
from datetime import datetime
from .models import InventoryItem, ProductHistory
from django.urls import reverse
import csv
from django.http import HttpResponse
from django import forms
from .forms import UserProfileForm
from django.contrib import messages
from django.core.mail import send_mail
from .models import EmailOTP
from .forms import OTPForm
from django.utils import timezone
from datetime import timedelta


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

@login_required
def product_manage(request, pk=None):
    from .forms import InventoryItemForm
    from .models import InventoryItem, ProductHistory, Category

    # Check if editing or adding
    if pk:
        item = get_object_or_404(InventoryItem, id=pk)
        edit_mode = True
    else:
        item = None
        edit_mode = False

    if request.method == "POST":
        if "delete" in request.POST:
            # 🗑 Save history BEFORE deleting product
            ProductHistory.objects.create(
                product=item,
                action="Deleted",
                description=f"You deleted the product '{item.product_name}'.",
                user=request.user,
            )
            item.delete()
            messages.success(request, "Product deleted successfully.")
            return redirect("product_manage")
        else:
            form = InventoryItemForm(request.POST, instance=item)
            if form.is_valid():
                product_code = form.cleaned_data["product_code"]

                # ✅ Check for duplicate product code (only when adding new)
                if not edit_mode and InventoryItem.objects.filter(product_code=product_code).exists():
                    messages.error(request, f"Product code '{product_code}' already exists. Please use another code.")
                else:
                    # Save normally
                    product = form.save(commit=False)
                    product.save()

                    if edit_mode:
                        ProductHistory.objects.create(
                            product=product,
                            action="Updated",
                            description=f"You updated the product '{product.product_name}'.",
                            user=request.user,
                        )
                        messages.success(request, "Product updated successfully.")
                    else:
                        ProductHistory.objects.create(
                            product=product,
                            action="Added",
                            description=f"You added a new product '{product.product_name}'.",
                            user=request.user,
                        )
                        messages.success(request, "Product added successfully.")

                    return redirect("product_manage")
    else:
        form = InventoryItemForm(instance=item)

    # 🔍 Search filter
    query = request.GET.get("q")
    items = InventoryItem.objects.all()
    if query:
        items = items.filter(product_name__icontains=query) | items.filter(product_code__icontains=query)

    # 🧾 Get Product History (latest first)
    history = ProductHistory.objects.order_by("-date")

    categories = Category.objects.all()

    return render(request, "inventory/manage_product.html", {
        "form": form,
        "items": items,
        "edit_mode": edit_mode,
        "history": history,
        "categories": categories,
    })

def index(request):
    return render(request, 'index.html')

@login_required
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
    from .models import Category, InventoryItem
    category = get_object_or_404(Category, pk=pk)

    # Check if category has linked products
    linked_products = InventoryItem.objects.filter(category=category)

    if linked_products.exists():
        messages.error(
            request,
            f"Cannot delete category '{category.category_name}' because it is linked to existing products."
        )
    else:
        category.delete()
        messages.success(request, f"Category '{category.category_name}' deleted successfully.")

    return redirect('category_list_add')

def product_detail(request, pk):
    product = get_object_or_404(InventoryItem, pk=pk)
    return render(request, 'inventory/product_detail.html', {
        'product': product
    })

@login_required
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

@login_required
def stock_history(request):
    history = StockHistory.objects.select_related('product').order_by('-date')

    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    action_filter = request.GET.get('action')

    # Filter by date range
    if start_date and end_date:
        start = make_aware(datetime.strptime(start_date, "%Y-%m-%d"))
        end = make_aware(datetime.strptime(end_date, "%Y-%m-%d"))
        history = history.filter(date__range=[start, end])

    # Filter by action type
    if action_filter:
        history = history.filter(action=action_filter)

    categories = Category.objects.all()  # pass categories to modal

    context = {
        'history': history,
        'categories': categories
    }
    return render(request, 'inventory/stock_history.html', context)

@login_required
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
            # Create user but inactive until email verification
            user = form.save(commit=False)
            password = form.cleaned_data['password']
            user.set_password(password)
            user.is_active = False
            user.save()

            # Create profile
            profile = UserProfile(
                user=user,
                gender=form.cleaned_data['gender'],
                role=form.cleaned_data['role'],
                picture=form.cleaned_data.get('picture'),
                is_verified=False,
                is_declined=False
            )
            profile.save()

            # Create OTP
            otp_record = EmailOTP(user=user)
            otp_record.generate_otp()

            # Send OTP email (console backend for testing)
            send_mail(
                'Your OTP Verification Code',
                f'Hello {user.username}, your OTP is {otp_record.otp_code}',
                'no-reply@freshmart.com',
                [user.email],
                fail_silently=False
            )

            # Save user id in session for OTP verification
            request.session['verify_user_id'] = user.id
            messages.success(request, "Account created! Please check your email for the OTP.")
            return redirect('verify_email')
        else:
            # Print form errors to console for debugging
            print(form.errors)
    else:
        form = UserRegistrationForm()

    return render(request, 'registration/register.html', {'form': form})


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

    pending_admins = UserProfile.objects.filter(
        role='Admin', 
        is_verified=False, 
        is_declined=False  # <-- exclude declined admins
    ).exclude(user=request.user)
    
    return render(request, 'admin_verification.html', {'pending_admins': pending_admins})


@login_required
@unverified_admin_or_superuser_required # Allows unverified admins and superusers
def approve_admin(request, profile_id):
    profile = get_object_or_404(UserProfile, id=profile_id)
    
    if request.method == 'POST':
        profile.is_verified = True
        profile.is_declined = False
        profile.user.is_active = True
        profile.user.save()
        profile.save()
        message = f"{profile.user.username}'s admin account has been approved."

        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JsonResponse({'success': True, 'message': message})
        else:
            messages.success(request, message)
            return redirect('admin_verification')


@login_required
@unverified_admin_or_superuser_required # Allows unverified admins and superusers
def decline_admin(request, profile_id):
    profile = get_object_or_404(UserProfile, id=profile_id)
    
    if request.method == 'POST':
        profile.is_verified = False
        profile.is_declined = True
        profile.user.is_active = True  # Keep active for login redirect
        profile.save()
        message = f"{profile.user.username}'s admin account has been declined."

        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JsonResponse({'success': True, 'message': message})
        else:
            messages.error(request, message)
            return redirect('admin_verification')


def waiting_verification(request):
    return render(request, 'waiting_verification.html')

def declined_verification(request):
    return render(request, 'declined_verification.html')

def custom_login(request):
    remaining_lock_seconds = 0  # Default: no lock

    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        username = request.POST.get("username")
        password = request.POST.get("password")

        # Try to get user and profile
        try:
            user = User.objects.get(username=username)
            profile = user.userprofile
        except (User.DoesNotExist, UserProfile.DoesNotExist):
            user = None
            profile = None

        # Check cooldown
        if profile and profile.lock_until and profile.lock_until > timezone.now():
            remaining_lock_seconds = int((profile.lock_until - timezone.now()).total_seconds())
            messages.error(
                request,
                f"Account locked. Try again in {remaining_lock_seconds // 60} minute(s)."
            )
        else:
            # Normal authentication
            if form.is_valid():
                user = authenticate(username=username, password=password)
                if user:
                    # Reset counters
                    if profile:
                        profile.failed_login_attempts = 0
                        profile.lock_until = None
                        profile.save()

                    login(request, user)
                    return redirect('index')

            # FAILED LOGIN
            if profile:
                profile.failed_login_attempts += 1
                if profile.failed_login_attempts % 5 == 0:
                    lock_minutes = 5 * (2 ** ((profile.failed_login_attempts // 5) - 1))
                    profile.lock_until = timezone.now() + timedelta(minutes=lock_minutes)
                    remaining_lock_seconds = int(lock_minutes * 60)
                profile.save()
                messages.error(request, "Invalid username or password.")

    else:
        form = AuthenticationForm()

    return render(request, "login.html", {
        "form": form,
        "remaining_lock_seconds": remaining_lock_seconds
    })

def category_quantity_data(request):
    """
    Returns JSON data for a pie chart showing total quantity per category.
    """
    # Annotate the Category queryset with the sum of all related InventoryItem quantities
    category_data = Category.objects.filter(
        inventoryitem__quantity_in_stock__gt=0 # Only include categories with stock > 0
    ).annotate(
        total_quantity=Sum('inventoryitem__quantity_in_stock')
    ).order_by('-total_quantity')

    # Format the data for the JavaScript chart library
    data = {
        'labels': [item.category_name for item in category_data],
        'quantities': [item.total_quantity for item in category_data],
    }
    
    # Return the data as a JSON response
    return JsonResponse(data)

def category_value_data(request):
    """
    Returns JSON data for a bar chart showing the total monetary value per category.
    """
    # 1. Aggregate the total value (quantity_in_stock * price) for each category.
    category_data = Category.objects.filter(
        # Only include categories that have products in stock
        inventoryitem__quantity_in_stock__gt=0 
    ).annotate(
        # Calculate the total value: SUM(quantity_in_stock * price)
        total_value=Sum(F('inventoryitem__quantity_in_stock') * F('inventoryitem__price'))
    ).order_by('-total_value') # Sort by highest value

    # 2. Format the data for the JavaScript chart library
    data = {
        'labels': [item.category_name for item in category_data],
        # Convert DecimalField values to float for JSON serialization
        'values': [float(item.total_value or 0) for item in category_data], 
    }
    
    # 3. Return the data as a JSON response
    return JsonResponse(data)

def product_price_data(request):
    """
    Returns JSON data for a line chart showing the prices of all products.
    """
    # Fetch all products, ordered by name for consistent charting
    products = InventoryItem.objects.all().order_by('product_name')
    
    data = {
        'labels': [product.product_name for product in products],
        # Convert DecimalField values to float for JSON serialization
        'prices': [float(product.price) for product in products],
    }
    
    return JsonResponse(data)

def product_value_data(request):
    """
    Returns JSON listing the top 12 products by total inventory value:
      total_value = quantity_in_stock * price
    """
    products = InventoryItem.objects.all()

    # Compute total value and store them temporarily
    product_values = []
    for p in products:
        price = float(p.price or 0)
        qty = p.quantity_in_stock or 0
        total = price * qty
        product_values.append({
            'name': p.product_name,
            'total_value': total
        })

    # Sort products by total value (descending)
    top_products = sorted(product_values, key=lambda x: x['total_value'], reverse=True)[:12]

    # Extract top 12 labels and values
    labels = [item['name'] for item in top_products]
    values = [item['total_value'] for item in top_products]

    return JsonResponse({
        "labels": labels,
        "values": values,
    })



def get_alerts(request):
    alerts = []

    # 1️⃣ Out of stock alerts
    out_of_stock_items = InventoryItem.objects.filter(quantity_in_stock=0)
    for item in out_of_stock_items:
        alerts.append({
            "type": "danger",
            "message": f"{item.product_name} is out of stock!",
            "url": reverse('stock_management')  # ✅ correct destination for stock issues
        })

    # 2️⃣ Almost out of stock alerts (1–20)
    almost_out_items = InventoryItem.objects.filter(quantity_in_stock__gte=1, quantity_in_stock__lte=20)
    for item in almost_out_items:
        alerts.append({
            "type": "warning",
            "message": f"{item.product_name} is almost out of stock!",
            "url": reverse('stock_management')  # ✅ same link
        })

    # 3️⃣ Pending admin verification alerts (for admins only)
    if (
        request.user.is_authenticated
        and hasattr(request.user, 'userprofile')
        and request.user.userprofile.role == 'Admin'
    ):
        pending_admin_count = UserProfile.objects.filter(
            role='Admin',
            is_verified=False,
            is_declined=False
        ).exclude(user=request.user).count()

        if pending_admin_count > 0:
            alerts.append({
                "type": "info",
                "message": f"{pending_admin_count} pending admin verification(s).",
                "url": reverse('admin_verification')  # ✅ correct link for admin verifications
            })

    return JsonResponse({
        "alerts": alerts,
        "count": len(alerts)
    })

def export_products_csv(request):
    if request.method == "POST":
        selected_categories = request.POST.getlist("categories")
        custom_filename = request.POST.get("filename", "").strip()  # Get the filename input

        # Use default name if blank
        if not custom_filename:
            custom_filename = "products"
        
        # Ensure .csv extension
        if not custom_filename.lower().endswith(".csv"):
            custom_filename += ".csv"

        # ✅ Set custom filename for download
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="{custom_filename}"'

        writer = csv.writer(response)
        writer.writerow(['Product Code', 'Product Name', 'Quantity', 'Price (₱)', 'Category'])

        # ✅ Handle category filtering
        if selected_categories and "all" not in selected_categories:
            items = InventoryItem.objects.filter(category__id__in=selected_categories)
        else:
            items = InventoryItem.objects.all()

        # ✅ Write data to CSV
        for item in items:
            writer.writerow([
                item.product_code,
                item.product_name,
                item.quantity_in_stock,
                f"{item.price:.2f}",
                item.category.category_name if item.category else "Uncategorized"
            ])

        return response

    # If GET request → show modal
    categories = Category.objects.all()
    return render(request, "inventory/export_modal.html", {"categories": categories})

@login_required
def user_profile(request):
    profile = request.user.userprofile
    return render(request, 'profile/profile_view.html', {'profile': profile})

@login_required
def edit_profile(request):
    profile = request.user.userprofile
    if request.method == 'POST':
        form = UserProfileForm(request.POST, request.FILES, instance=profile, user=request.user)
        if form.is_valid():
            # Save user fields
            request.user.first_name = form.cleaned_data['first_name']
            request.user.last_name = form.cleaned_data['last_name']
            request.user.email = form.cleaned_data['email']
            request.user.save()
            # Save profile fields
            form.save()
            messages.success(request, 'Profile updated successfully!')
            return redirect('user_profile')
    else:
        form = UserProfileForm(instance=profile, user=request.user)
    return render(request, 'profile/edit_profile.html', {'form': form, 'profile': profile})

def export_stock_csv(request):
    # Get filters
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    action = request.GET.get('action')
    category_id = request.GET.get('category')
    filename = request.GET.get('filename', '').strip()  # <-- get filename from modal

    if not filename:
        filename = 'stock_history'
    if not filename.lower().endswith('.csv'):
        filename += '.csv'

    queryset = StockHistory.objects.all().select_related('product', 'product__category')

    if start_date:
        queryset = queryset.filter(date__date__gte=start_date)
    if end_date:
        queryset = queryset.filter(date__date__lte=end_date)
    if action:
        queryset = queryset.filter(action=action)
    if category_id:
        queryset = queryset.filter(product__category_id=category_id)

    # Create response
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'  # <-- dynamic filename

    writer = csv.writer(response)
    writer.writerow(['Product Code', 'Product Name', 'Old Quantity', 'Input Quantity', 'New Quantity', 'Action', 'Date', 'Category'])

    for item in queryset:
        writer.writerow([
            item.product.product_code,
            item.product.product_name,
            item.old_quantity,
            item.input_quantity,
            item.new_quantity,
            item.get_action_display(),
            item.date.strftime("%Y-%m-%d %H:%M"),
            item.product.category.category_name if item.product.category else ''
        ])

    return response

def verify_email(request):
    user_id = request.session.get('verify_user_id')
    if not user_id:
        return redirect('registration')  # no session, go back to register

    otp_record = get_object_or_404(EmailOTP, user_id=user_id)

    if request.method == 'POST':
        form = OTPForm(request.POST)
        if form.is_valid():
            otp_input = form.cleaned_data['otp']
            if otp_record.otp_code == otp_input:
                user = otp_record.user
                user.is_active = True
                user.save()
                otp_record.delete()  # remove OTP record
                messages.success(request, "Email verified successfully!")
                return redirect('login')
            else:
                form.add_error('otp', 'Invalid OTP')
    else:
        form = OTPForm()

    return render(request, 'verify_email.html', {'form': form})