from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Employee, Products, CartItem, Cart, UserProfile, Order, OrderItem
from rest_framework.pagination import PageNumberPagination
from .serializers import (EmployeeSerializer ,ProductSerializer, CartSerializer, 
CartItemSerializer, AddToCartSerializer,SignupSerializer,orderitemserializer,orderserializer, CashfreeOrderSerializer)
from rest_framework.parsers import MultiPartParser, FormParser
from django.http import Http404, JsonResponse
from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticated,AllowAny
from .permissions import IsSeller
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth.models import User
from .forms import ProductsForm
from django.db import transaction
import uuid, json, hashlib, hmac, requests
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator


#signup users view 
class SignupView(APIView):
    def post(self, request):
        serializer = SignupSerializer(data=request.data)
        if serializer.is_valid():
            user = User.objects.create_user(
                username=serializer.validated_data['username'],
                email=serializer.validated_data['email'],
                password=serializer.validated_data['password']
            )

            role = serializer.validated_data.get('role', 'customer') 
            phone = serializer.validated_data['phone'] 
            
            # Ensure the UserProfile role is updated correctly
            user_profile, created = UserProfile.objects.get_or_create(user=user)
            user_profile.role = role  
            user_profile.phone = phone
            user_profile.save()

            return Response({
                "message": "User registered successfully",
                "username": user.username,
                "phone": user_profile.phone,
                "role": user_profile.role
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        
# User Login View
class LoginView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        try:
            user = User.objects.get(username=username)
            if user.check_password(password):
                refresh = RefreshToken.for_user(user)
                return Response({
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                }, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)


# Protected View (Only Accessible with JWT Token)
class ProtectedView(APIView):
    authentication_classes = [JWTAuthentication]  
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": "You are authenticated!"}, status=status.HTTP_200_OK)


# Refresh Token View (To Get a New Access Token)
class RefreshTokenView(APIView):
    def post(self, request):
        refresh_token = request.data.get("refresh")
        try:
            refresh = RefreshToken(refresh_token)
            new_access_token = refresh.access_token
            return Response({"access": str(new_access_token)}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": "Invalid refresh token"}, status=status.HTTP_401_UNAUTHORIZED)


class EmployeeList(APIView):
    def get(self, request):
        employees = Employee.objects.all()

        # Apply pagination
        paginator = PageNumberPagination()
        paginator.page_size = 10  
        result_page = paginator.paginate_queryset(employees, request)

        if result_page is not None:
            serializer = EmployeeSerializer(result_page, many=True)
            return paginator.get_paginated_response(serializer.data)  

        # Fallback response if pagination fails
        return Response({"error": "Pagination failed"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

    def post(self, request):
        """Handles both single and bulk employee creation."""
        if isinstance(request.data, list):
            many = True
        elif isinstance(request.data, dict):
            many = False
            request.data = [request.data]  # Convert single object to list
        else:
            return Response({"error": "Invalid data format"}, status=status.HTTP_400_BAD_REQUEST)

        serializer = EmployeeSerializer(data=request.data, many=many)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Employees added successfully"}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EmpDetails(APIView):
    """Handles retrieving, updating, and deleting a specific employee."""

    def get(self, request, pk):
        employee = get_object_or_404(Employee, pk=pk)
        serialize = EmployeeSerializer(employee)
        return Response(serialize.data, status=status.HTTP_200_OK)

    def put(self, request, pk):
        """Updates an existing employee."""
        emp = get_object_or_404(Employee, pk=pk)  # Get existing employee
        serialize = EmployeeSerializer(emp, data=request.data)  

        if serialize.is_valid():
            serialize.save()
            return Response(serialize.data, status=status.HTTP_200_OK)

        return Response(serialize.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        """Deletes an employee."""
        emp = get_object_or_404(Employee, pk=pk)
        emp.delete()
        return Response({"message": "Employee deleted successfully"}, status=status.HTTP_204_NO_CONTENT)


class ProductsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        product = Products.objects.all()

        # Apply pagination
        paginator = PageNumberPagination()
        paginator.page_size = 10  
        result_page = paginator.paginate_queryset(product, request)
    
        if result_page is not None:
            serializer = ProductSerializer(result_page, many=True)
            return paginator.get_paginated_response(serializer.data)  

        # Fallback response if pagination fails
        return Response({"error": "Pagination failed"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class AddProductView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated,IsSeller]
    parser_classes = (MultiPartParser, FormParser)  

    def post(self, request):
        form = ProductsForm(request.POST, request.FILES)  # Use request.FILES for images
        if form.is_valid():
            product = form.save()
            serializer = ProductSerializer(product)
            return Response({
                "message": "Product added successfully!",
                "product": {
                    "id": product.id,
                    "name": product.name,
                    "description": product.description,
                    "price": str(product.price),
                    "stock":product.stock,
                    "image": product.image.url if product.image else None  # Corrected image handling
                }
            }, status=status.HTTP_201_CREATED)
        return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)
    

class CartView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated,IsSeller]
    
    def get(self, request):
        """View the current cart"""
        cartt = get_object_or_404(Cart, user=request.user)
        serializer = CartSerializer(cartt)
        return Response(serializer.data, status=status.HTTP_200_OK)

class AddToCartView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """Add a product to the cart"""
        serializer = AddToCartSerializer(data=request.data)

        if serializer.is_valid():
            product_id = serializer.validated_data['product_id']
            quantity = serializer.validated_data['quantity']

            product = get_object_or_404(Products, id=product_id)
            cart, created = Cart.objects.get_or_create(user=request.user)
            cart_item, created = CartItem.objects.get_or_create(cart=cart, product=product)

            cart_item.quantity += quantity
            cart_item.save()

            return Response({"message": "Product added to cart successfully"}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class RemoveFromCartView(APIView):


    def post(self, request):
        """Remove a product from the cart"""
        product_id = request.data.get('product_id')

        cart = get_object_or_404(Cart, user=request.user)
        cart_item = get_object_or_404(CartItem, cart=cart, product__id=product_id)

        cart_item.delete()

        return Response({"message": "Product removed from cart successfully"}, status=status.HTTP_200_OK)


class productdetails(APIView):
    """Handles retrieving, updating, and deleting a specific products."""

    def get(self, request, pk):
        products = get_object_or_404(products, pk=pk)
        serialize = ProductSerializer(products)
        return Response(serialize.data, status=status.HTTP_200_OK)

    def put(self, request, pk):
        """Updates an existing products."""

        prod = get_object_or_404(Products, pk=pk)  
        serialize = ProductSerializer(prod, data=request.data)  

        if serialize.is_valid():
            serialize.save()
            return Response(serialize.data, status=status.HTTP_200_OK)

        return Response(serialize.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        """Deletes an products."""
        produ = get_object_or_404(Products, pk=pk)
        produ.delete()
        return Response({"message": "product deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
    


#checkout page
class CheckoutView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]  

    def post(self, request):
        """Handles the checkout process for the user."""
        user = request.user
        
        # Fetch user's cart
        cart = get_object_or_404(Cart, user=user)
        cart_items = CartItem.objects.filter(cart=cart)

        if not cart_items.exists():
            return Response({"error": "Your cart is empty!"}, status=status.HTTP_400_BAD_REQUEST)


        # Get user address
        address = request.data.get("address")
        if not address:
            profile = UserProfile.objects.get(user=user)
            if not profile.address:
                return Response({"error": "Address is required"}, status=status.HTTP_400_BAD_REQUEST)
            address = profile.address  # Use saved address if not provided


        # Ensure all products are in stock
        for item in cart_items:
            if item.quantity > item.product.stock:
                return Response({"error": f"Not enough stock for {item.product.name}"}, status=status.HTTP_400_BAD_REQUEST)

        # Create order inside a transaction to prevent partial failures
        with transaction.atomic():
            order = Order.objects.create(user=user, total_price=0)
            total_price = 0

            for item in cart_items:
                # Create order items
                order_item = OrderItem.objects.create(
                    order=order,
                    product=item.product,
                    quantity=item.quantity,
                    price=item.product.price
                )
                
                # Deduct stock
                item.product.stock -= item.quantity
                item.product.save()

                total_price += item.product.price * item.quantity

            # Update order total price
            order.total_price = total_price
            order.save()

            # Clear cart
            cart_items.delete()

        return Response({
            "message": "Checkout successful!",
            "order_id": order.id,
            "total_price": total_price
        }, status=status.HTTP_201_CREATED)


class OrderHistoryView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user

        # Use the correct field name from the Order model
        order_items = OrderItem.objects.filter(order__user=user).select_related('product')

        serializer = orderitemserializer(order_items, many=True)
        return Response(serializer.data)

"""
# cashfree order creating using api
class CreateCashfreeOrderView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user

        # Fetch the latest order for the user
        try:
            order = Order.objects.filter(user=user).latest('created_at')
        except Order.DoesNotExist:
            return Response({"error": "No order found for this user"}, status=status.HTTP_404_NOT_FOUND)

        # Serialize the order
        serializer = CashfreeOrderSerializer(order)

        # Construct the order ID
        order_id = f"CF_{order.id}"
        amount = order.total_price

        # Define API URL (Sandbox for testing)
        url = "https://sandbox.cashfree.com/pg/orders"

        # Set Headers
        headers = {
            "Content-Type": "application/json",
            "x-client-id": settings.CASHFREE_CLIENT_ID,
            "x-client-secret": settings.CASHFREE_CLIENT_SECRET,
            "x-api-version": "2022-09-01"
        }

        # Construct request data
        data = {
            "order_id": order_id,
            "order_amount": float(amount),
            "order_currency": "INR",
            "customer_details": {
                "customer_id": str(user.id),
                "customer_name": serializer.data["customer_name"],
                "customer_email": serializer.data["customer_email"],
                "customer_phone": serializer.data["customer_phone"]
            },
            "order_meta": {
                "return_url": f"http://127.0.0.1:8000/api/cashfree/verify?order_id={order_id}"
            }
        }

        # Send POST request to Cashfree
        response = requests.post(url, json=data, headers=headers)
        payment_data = response.json()

        if response.status_code == 200:
            payment_data = response.json()
            if "payments" in payment_data and "url" in payment_data["payments"]:
                return Response({"payment_link": payment_data["payments"]["url"]}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "payment_link not found", "response": payment_data}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(response.json(), status=status.HTTP_400_BAD_REQUEST)   """


"""

@method_decorator(csrf_exempt, name='dispatch')
class CashfreeWebhookAPIView(APIView):
    def post(self, request, *args, **kwargs):
        print("Webhook received:", request.body.decode())  # Debugging
        
        try:
            # Load JSON data
            data = json.loads(request.body)

            # Extract order details correctly
            order_data = data.get("data", {}).get("order", {})
            payment_data = data.get("data", {}).get("payment", {})

            order_id = order_data.get("order_id")
            payment_status = payment_data.get("payment_status")  # 'SUCCESS', 'FAILED'

            if not order_id or not payment_status:
                return Response({"error": "Missing order_id or payment_status"}, status=status.HTTP_400_BAD_REQUEST)

            print("Order ID:", order_id)
            print("Payment Status:", payment_status)

            # Update order status in your database
            from myapp.models import Order  # Import your Order model
            try:
                order = Order.objects.get(order_id=order_id)
                order.payment_status = payment_status  # Update status
                order.save()
                return Response({"message": "Payment status updated"}, status=status.HTTP_200_OK)
            except Order.DoesNotExist:
                return Response({"error": "Order not found"}, status=status.HTTP_404_NOT_FOUND)

        except json.JSONDecodeError:
            return Response({"error": "Invalid JSON data"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print("Error:", str(e))
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)"""

"""

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.conf import settings
from cashfree_pg.api_client import Cashfree
from cashfree_pg.models.create_order_request import CreateOrderRequest
from cashfree_pg.models.customer_details import CustomerDetails
from cashfree_pg.models.order_meta import OrderMeta
from .models import Order, User
import json

# Configure Cashfree
Cashfree.XClientId = settings.CASHFREE_CLIENT_ID
Cashfree.XClientSecret = settings.CASHFREE_CLIENT_SECRET
Cashfree.XEnvironment = Cashfree.SANDBOX  # Change to PRODUCTION in live
x_api_version = "2023-08-01"

@csrf_exempt
@require_POST
def create_cashfree_order(request):
    try:
        data = json.loads(request.body)
        order_id = data.get("order_id")
        
        # Fetch order details from database
        order = Order.objects.get(id=order_id)
        user = order.user  # Assuming Order model has a ForeignKey to User

        customer_phone = str(UserProfile.phone).strip()

        # Ensure the phone number is exactly 10 digits
        if not customer_phone.isdigit() or len(customer_phone) != 10:
            return JsonResponse({"error": "Invalid phone number format"}, status=400)
        
        # Create customer details
        customer_details = CustomerDetails(
        customer_id=str(order.user.id).zfill(3),  # Ensure at least 3 characters
        customer_phone=customer_phone,  # Ensure max 10 digits,  # Convert phone to string
        customer_email=order.user.email
)



        # Set return URL
        return_url = f"http://127.0.0.1:8000/api/cashfree/verify?order_id={order_id}"
        order_meta = OrderMeta(return_url=return_url)
        
        # Create order request payload
        create_order_request = CreateOrderRequest(
            order_amount=float(order.total_price),
            order_currency="INR",
            customer_details=customer_details,
            order_meta=order_meta
        )
        
        # Call Cashfree API to create order
        api_response = Cashfree().PGCreateOrder(x_api_version, create_order_request, None, None)
        return JsonResponse(api_response.data, safe=False)
    
    except Order.DoesNotExist:
        return JsonResponse({"error": "Order not found"}, status=404)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
@require_POST
def cashfree_webhook(request):
    try:
        signature = request.headers.get('x-webhook-signature')
        timestamp = request.headers.get('x-webhook-timestamp')
        raw_body = request.body.decode('utf-8')
        
        # Verify webhook signature
        webhook_event, err = Cashfree().PGVerifyWebhookSignature(signature, raw_body, timestamp)
        if err is not None:
            return JsonResponse({"error": "Invalid webhook signature"}, status=400)
        
        event_data = webhook_event['object']
        order_id = event_data["data"]["order"]["order_id"]
        payment_status = event_data["data"]["payment"]["payment_status"]
        
        # Update order status in database
        order = Order.objects.get(id=order_id)
        order.payment_status = payment_status
        order.save()
        
        return JsonResponse({"message": "Webhook processed successfully"}, status=200)
    except Order.DoesNotExist:
        return JsonResponse({"error": "Order not found"}, status=404)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
"""



from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import requests
import hmac
import hashlib
import base64
import json
from django.conf import settings
from .models import Order, UserProfile
"""from cashfree_pg.api_client import Cashfree"""
#from cashfree_pg.models.customer_details import CustomerDetails
#from cashfree_pg.models.order_meta import OrderMeta

class InitiatePaymentView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            user = request.user
            order = Order.objects.filter(user=user, payment_status='PENDING').latest('created_at')
            user_profile = get_object_or_404(UserProfile, user=user)

            # Prepare order data for Cashfree
            order_data = {
                "order_id": str(order.id),
                "order_amount": float(order.total_price),
                "order_currency": "INR",
                "customer_details": {
                    "customer_id": str(user.id),
                    "customer_name": user.get_full_name(),
                    "customer_email": user.email,
                    "customer_phone": str(user_profile.phone).strip()
                },
                "order_meta": {
                    "return_url": f"http://127.0.0.1:8000/api/cashfree/verify?order_id={order.id}",
                    "payment_methods": "cc,dc,upi,nb"
                }
            }

            # Call Cashfree API to create the order
            headers = {
                "x-client-id": settings.CASHFREE_CLIENT_ID,
                "x-client-secret": settings.CASHFREE_CLIENT_SECRET,
                "x-api-version": "2023-08-01",
                "Content-Type": "application/json"
            }

            order_response = requests.post(
                "https://sandbox.cashfree.com/pg/orders",
                json=order_data,
                headers=headers
            )

            if order_response.status_code != 200:
                return Response(
                    {"error": "Failed to create order", "details": order_response.json()},
                    status=status.HTTP_400_BAD_REQUEST
                )

            order_response_data = order_response.json()
            payment_session_id = order_response_data.get("payment_session_id")

            if not payment_session_id:
                return Response(
                    {"error": "Payment session ID not received"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Construct the payment link
            payment_url = f"https://sandbox.cashfree.com/pg/view/checkout/{payment_session_id}"


            return Response({
                "message": "Order created successfully",
                "payment_url": payment_url,
                "cashfree_order_id": order_response_data.get("cf_order_id"),
                "payment_session_id": payment_session_id
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": f"Unexpected error: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class WebhookView(APIView):
    def post(self, request):
        try:
            signature = request.headers.get('x-webhook-signature')
            timestamp = request.headers.get('x-webhook-timestamp')
            raw_body = request.body.decode('utf-8')

            # Verify webhook signature
            if not self.verify_signature(signature, raw_body, timestamp):
                return Response({"error": "Invalid signature"}, status=status.HTTP_400_BAD_REQUEST)

            # Process webhook data
            webhook_data = json.loads(raw_body)
            order_id = webhook_data["data"]["order"]["id"]
            payment_status = webhook_data["data"]["payment"]["payment_status"]

            # Update order status in database
            order = Order.objects.get(id=order_id)
            order.payment_status = payment_status  # Update payment status
            order.save()

            return Response({"message": "Webhook processed successfully"}, status=status.HTTP_200_OK)

        except Order.DoesNotExist:
            return Response({"error": "Order not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def verify_signature(self, signature, raw_body, timestamp):
        try:
            signature_string = timestamp + raw_body
            hmac_obj = hmac.new(settings.CASHFREE_SECRET_KEY.encode(), signature_string.encode(), hashlib.sha256)
            generated_signature = base64.b64encode(hmac_obj.digest()).decode()
            return generated_signature == signature
        except Exception:
            return False
