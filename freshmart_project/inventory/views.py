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
            # Create User
            user = User.objects.create_user(
                username=form.cleaned_data['username'],
                email=form.cleaned_data['email'],
                first_name=form.cleaned_data['first_name'],
                last_name=form.cleaned_data['last_name'],
                password=form.cleaned_data['password']
            )
            # Create UserProfile
            UserProfile.objects.create(
                user=user,
                gender=form.cleaned_data['gender'],
                role=form.cleaned_data['role'],
                picture=form.cleaned_data.get('picture')
            )
            messages.success(request, "Registration successful! Please log in.")
            return redirect('login')
    else:
        form = UserRegistrationForm()
    return render(request, 'registration/register.html', {'form': form})

def admin_required(view_func):
    def wrapper(request, *args, **kwargs):
        if request.user.is_authenticated and request.user.userprofile.role == 'Admin':
            return view_func(request, *args, **kwargs)
        else:
            return HttpResponseForbidden("You do not have permission to access this page.")
    return wrapper

