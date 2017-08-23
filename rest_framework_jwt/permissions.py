# -*- coding: utf-8 -*-
#
#
#   Name:
#       permissions.py
#
#   Description
#
#   Author:
#       Andres Navarro
#
#   Version:
#       0.1
#

"""
Provides a set of pluggable permission policies.
"""
#from __future__ import unicode_literals

#from django.http import Http404
#from rest_framework.compat import is_authenticated
from rest_framework import exceptions

SAFE_METHODS = ('GET', 'HEAD', 'OPTIONS')


class BasePermission(object):
    """
    A base class from which all permission classes should inherit.
    """

    def has_permission(self, request, view):
        """
        Return `True` if permission is granted, `False` otherwise.
        """
        return True

    def has_object_permission(self, request, view, obj):
        """
        Return `True` if permission is granted, `False` otherwise.
        """
        return True

    def check_role(self,request,view, array):
        try:
            if request.user[1] in array:
                return True
            else:
                raise exceptions.PermissionDenied({"error":23})
        except:
            raise exceptions.PermissionDenied({"error":23})


class AllowAny(BasePermission): 
    """
    Allow any access.
    This isn't strictly required, since you could use an empty
    permission_classes list, but it's useful because it makes the intention
    more explicit.
    """

    def has_permission(self, request, view):
        return True

class NotAllowAny(BasePermission): 
    """
    Allow any access.
    This isn't strictly required, since you could use an empty
    permission_classes list, but it's useful because it makes the intention
    more explicit.
    """

    def has_permission(self, request, view):
        return False

class Global(BasePermission): 
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global'])

class Client(BasePermission): 
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Client'])

class Kronero(BasePermission): 
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Kronero'])

class ApplicationGlobal(BasePermission): 
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Application'])

class Store(BasePermission): 
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Store'])

class Chain(BasePermission):
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Chain']) 

class ClientKronero(BasePermission):
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Client','Kronero']) 

class ClientApplication(BasePermission):
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Client','Application']) 

class ClientStore(BasePermission):
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Client','Store']) 

class ClientChain(BasePermission):
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Client','Chain']) 

class KroneroApplication(BasePermission):
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Kronero','Application']) 

class KroneroStore(BasePermission):
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Kronero','Store']) 

class KroneroChain(BasePermission):
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Kronero','Chain']) 

class ApplicationStore(BasePermission):
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Application', 'Store']) 

class ApplicationChain(BasePermission):
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Application','Chain']) 

class StoreChain(BasePermission):
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Store','Chain']) 

class ClientKroneroApplication(BasePermission):
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Client','Kronero','Application']) 

class ClientKroneroStore(BasePermission):
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Client','Kronero','Store']) 

class ClientKroneroChain(BasePermission):
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Client','Kronero','Chain']) 

class ClientApplicationStore(BasePermission):
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Client','Application','Store']) 

class ClientApplicationChain(BasePermission):
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Client','Application','Chain']) 

class ClientStoreChain(BasePermission):
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Client','Store','Chain']) 

class KroneroApplicationStore(BasePermission):
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Kronero','Application','Store']) 

class KroneroApplicationChain(BasePermission):
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Kronero','Application','Chain']) 

class KroneroStoreChain(BasePermission):
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Kronero','Store','Chain']) 

class ApplicationStoreChain(BasePermission):
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Application','Store','Chain']) 

class ClientKroneroApplicationStore(BasePermission):
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Client','Kronero','Application','Store'])

class ClientKroneroApplicationChain(BasePermission):
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Client','Kronero','Application','Chain'])

class ClientKroneroStoreChain(BasePermission):
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Client','Kronero','Store','Chain']) 

class ClientApplicationStoreChain(BasePermission):
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Client','Application','Store','Chain']) 

class KroneroApplicationChainStore(BasePermission):
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Kronero','Application','Store','Chain']) 

class ClientKroneroApplicationChainStore(BasePermission):
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Global','Client','Kronero','Application','Store','Chain']) 

class OnlyClient(BasePermission): 
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Client'])

class OnlyKronero(BasePermission): 
    """
    """
    def has_permission(self, request, view):
        return self.check_role(request,view, ['Kronero'])