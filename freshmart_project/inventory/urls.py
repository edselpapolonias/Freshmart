from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('', views.dashboard, name='index'),   
    path('products/', views.product_manage, name='product_manage'),
    path('products/edit/<int:pk>/', views.product_manage, name='product_edit'),
    path('products/<int:pk>/', views.product_detail, name='product_detail'),

    path('categories/', views.category_list_add, name='category_list_add'),
    path('categories/edit/<int:pk>/', views.category_edit, name='category_edit'),
    path('categories/delete/<int:pk>/', views.category_delete, name='category_delete'),

    path('stock/', views.stock_management, name='stock_management'),
    path('stock-history/', views.stock_history, name='stock_history'),

    path('register/', views.register, name='registration'),
    path('login/', auth_views.LoginView.as_view(template_name='login.html'), name='login'),
    path('user-list/', views.user_list, name='user_list'),

    path('logout/', views.logout_view, name='logout'),

    path('admin_verification/', views.admin_verification, name='admin_verification'),
    path('admin_verification/approve/<int:profile_id>/', views.approve_admin, name='approve_admin'),
    path('admin_verification/decline/<int:profile_id>/', views.decline_admin, name='decline_admin'),
    path('waiting_verification/', views.waiting_verification, name='waiting_verification'),
    path('declined_verification/', views.declined_verification, name='declined_verification'),

]


