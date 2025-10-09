from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),   
    path('item/list', views.item_list, name='item_list'),
    path('item/<int:pk>/', views.item_detail, name='item_detail'),
    path('item/add/', views.item_add, name='item_add'),
    path('item/edit/<int:pk>/', views.item_edit, name='item_edit'),
    path('item/delete/<int:pk>/', views.item_delete, name='item_delete'),
]
