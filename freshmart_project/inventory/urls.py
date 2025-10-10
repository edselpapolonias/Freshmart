from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),   
    path('products/', views.product_manage, name='product_manage'),
    path('products/edit/<int:pk>/', views.product_manage, name='product_edit'),
    path('products/<int:pk>/', views.product_detail, name='product_detail'),

    path('categories/', views.category_list_add, name='category_list_add'),
    path('categories/edit/<int:pk>/', views.category_edit, name='category_edit'),
    path('categories/delete/<int:pk>/', views.category_delete, name='category_delete'),

    path('stock/', views.stock_management, name='stock_management'),

]
