from django.urls import path
from .views import (
    LoginView, ProtectedView, RefreshTokenView,
    EmployeeList, EmpDetails, ProductsView, AddProductView, 
    CartView, AddToCartView, RemoveFromCartView, productdetails, 
    CheckoutView,OrderHistoryView,WebhookView,InitiatePaymentView
)

urlpatterns = [
    
    path('login/', LoginView.as_view(), name='login'),
    path('protected/', ProtectedView.as_view(), name='protected'),
    path('refresh-token/', RefreshTokenView.as_view(), name='refresh_token'),
    path('employees/', EmployeeList.as_view(), name='employee-list'),
    path('employees/<int:pk>/', EmpDetails.as_view(),name='emp-details'),
    path('products/', ProductsView.as_view(), name='products'),
    path('products/add/', AddProductView.as_view(), name='add-product'),
    path('cart/', CartView.as_view(), name='cart'),
    path('cart/add/', AddToCartView.as_view(), name='add-to-cart'),
    path('cart/remove/', RemoveFromCartView.as_view(), name='remove-items'),
    path('product/<int:pk>/', productdetails.as_view(), name='product-details'),
    path('checkout/',CheckoutView.as_view(), name = 'check-out'),
    path('orders',OrderHistoryView.as_view(),name= 'oreders'),
    path('create-order/', InitiatePaymentView.as_view(), name='create_cashfree_order'),
    path('webhook/', WebhookView.as_view(), name='webhook'),



]
