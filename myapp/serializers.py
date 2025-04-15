from rest_framework import serializers
from .models import Employee, Products, Cart, CartItem, UserProfile, OrderItem, Order
from django.contrib.auth.models import User



class EmployeeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Employee
        fields = '__all__'



class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Products
        fields = '__all__'




class CartItemSerializer(serializers.ModelSerializer):
    product = ProductSerializer()

    class Meta:
        model = CartItem
        fields = '__all__'



class CartSerializer(serializers.ModelSerializer):
    cart_items = CartItemSerializer(many=True, read_only=True)

    class Meta:
        model = Cart
        fields = '__all__'


class AddToCartSerializer(serializers.Serializer):
    product_id = serializers.IntegerField()
    quantity = serializers.IntegerField(min_value=1, default=1)

    def validate_product_id(self, value):
        if not Products.objects.filter(id=value).exists():
            raise serializers.ValidationError("Product not found.")
        return value
    


class UserSerializer(serializers.ModelSerializer):
    role = serializers.ChoiceField(choices=UserProfile.ROLE_CHOICES, default='customer')
    phone = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ['username', 'password', 'role', 'email','phone']
        extra_kwargs = {'password': {'write_only': True}}


    def validate_phone(self, value):
        """Ensure phone number is unique."""
        if UserProfile.objects.filter(phone=value).exists():
            raise serializers.ValidationError("Phone number already exists.")
        return value

    def create(self, validated_data):
        role = validated_data.pop('role', 'customer')  # Get role and remove from data
        phone = validated_data.pop('phone')
        user = User.objects.create_user(**validated_data)
        UserProfile.objects.create(user=user, role=role)  # Create profile
        return user
    

class SignupSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    email = serializers.EmailField(required=False, allow_blank=True)  # Email is optional
    password = serializers.CharField(write_only=True, min_length=8)
    phone = serializers.CharField(max_length=15, required=True)  # Ensure phone is required
    role = serializers.ChoiceField(choices=['customer', 'seller', 'admin'], default='customer')

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username already taken.")
        return value

    def validate_email(self, value):
        if value and User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already registered.")
        return value

    def validate_phone(self, value):
        """Ensure phone number is unique."""
        if UserProfile.objects.filter(phone=value).exists():
            raise serializers.ValidationError("Phone number already exists.")
        return value

    def create(self, validated_data):
        """Create user and associated UserProfile."""
        role = validated_data.pop('role', 'customer')  
        phone = validated_data.pop('phone')  
        email = validated_data.pop('email', None)  # Email is optional

        user = User.objects.create_user(email=email, **validated_data)  
        UserProfile.objects.create(user=user, role=role, phone=phone)  

        return user

    

class CheckoutSerializer(serializers.Serializer):
    address = serializers.CharField(required=True)


class orderserializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = '__all__'



class orderitemserializer(serializers.ModelSerializer):
    class Meta:
        model = OrderItem
        fields = '__all__' 


class CashfreeOrderSerializer(serializers.ModelSerializer):
    customer_name = serializers.CharField(source='user.username', read_only=True)
    customer_email = serializers.EmailField(source='user.email', read_only=True)
    customer_phone = serializers.CharField(source='user.userprofile.phone', read_only=True)  

    class Meta:
        model = Order
        fields = ['id', 'total_price', 'customer_name', 'customer_email', 'customer_phone']