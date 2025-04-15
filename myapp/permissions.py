from rest_framework.permissions import BasePermission



class IsAuthenticatedUser(BasePermission):
    """
    Grants access only to authenticated users.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated


class IsSeller(BasePermission):
    """
    Grants access only to users with the 'seller' role.
    """

    message = "You must be a seller to access this resource."

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            self.message = "Authentication is required."
            return False
        
        if not hasattr(request.user, 'userprofile'):
            self.message = "User profile is missing."
            return False

        if request.user.userprofile.role != "seller":
            self.message = "Only sellers are allowed."
            return False

        return True
    
class IsOwner(BasePermission):
    """
    Grants permission only if the user is modifying their own data.
    """
    def has_object_permission(self, request, view, obj):
        return obj.user == request.user



class IsCustomer(BasePermission):
    """
    Grants access only to users with the 'customer' role.
    """
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.userprofile.role == "customer"
