from django.db import models
from django.contrib.auth.models import User



class Employee(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    age = models.IntegerField()
    department = models.CharField(max_length=50)
    salary = models.DecimalField(max_digits=10, decimal_places=2)
    join_date = models.DateField(auto_now_add=True)

    def __str__(self):
        return self.name
    

class Products(models.Model): 

    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    stock = models.IntegerField(blank= False, null= False,default=0)
    image = models.ImageField(upload_to='product_images/', blank=True, null=True)

    def __str__(self):
        return self.name

class Cart(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='carts')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Cart for {self.user.username}"

class CartItem(models.Model):
    cart = models.ForeignKey(Cart, on_delete=models.CASCADE, related_name='cart_items')
    product = models.ForeignKey(Products, on_delete=models.CASCADE, related_name='cart_items')
    quantity = models.PositiveIntegerField(default=1)
    added_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.quantity} x {self.product.name} in cart"

    def total_price(self):
        return self.product.price * self.quantity


class UserProfile(models.Model):
    ROLE_CHOICES = [
        ('seller', 'Seller'),
        ('customer', 'Customer'),
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='customer')
    address = models.TextField(blank=True, null=True, default= "arrdess")  # New address field
    phone = models.CharField(max_length=15)  # Ensure this line exists



    def __str__(self):
        return f"{self.user.username} - {self.role}"


class Order(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    total_price = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)
    address = models.TextField(default = 'no address') 
    payment_status = models.CharField(
        max_length=20,
        choices=[("PENDING", "Pending"), ("PAID", "Paid"), ("FAILED", "Failed"), ("REFUNDED", "Refunded")],
        default="PENDING",
    )  # NEW FIELD to store payment status

    def __str__(self):
        return f"Order {self.order_id} - {self.payment_status} - {self.user} x {self.total_price}"




class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name="items")
    product = models.ForeignKey(Products, on_delete=models.PROTECT)
    quantity = models.PositiveIntegerField()    
    price = models.DecimalField(max_digits=10, decimal_places=2)  # Store price at time of order

    def __str__(self):
        return f"{self.product.id} x {self.order.id} "