from django.shortcuts import render, get_object_or_404, redirect
from .models import InventoryItem
from .forms import InventoryItemForm
from django.shortcuts import render
from .forms import CategoryForm 
from .models import Category

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