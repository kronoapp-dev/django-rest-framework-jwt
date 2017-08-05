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
from __future__ import unicode_literals

from django.http import Http404
from rest_framework.compat import is_authenticated

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


class AllowAny(BasePermission):
    """
    Allow any access.
    This isn't strictly required, since you could use an empty
    permission_classes list, but it's useful because it makes the intention
    more explicit.
    """

    def has_permission(self, request, view):
        return True


class IsAuthenticated(BasePermission):
    """
    Allows access only to authenticated users.
    """

    def has_permission(self, request, view):
        #print(request.user)
        return True
        #return request.user and is_authenticated(request.user)


class IsAdminUser(BasePermission):
    """
    Allows access only to admin users.
    """

    def has_permission(self, request, view):
        #print(request.user)
        return True
        #return request.user and request.user.is_staff


class IsAuthenticatedOrReadOnly(BasePermission):
    """
    The request is authenticated as a user, or is a read-only request.
    """

    def has_permission(self, request, view):
        print(request.user)
        return True
        #return (
        #    request.method in SAFE_METHODS or
        #    request.user and
        #    is_authenticated(request.user)
        #)

class IsAuthenticated_0(BasePermission):
    """
    """

    def has_permission(self, request, view):
        return True


class IsAuthenticated_1(BasePermission):
    """
    """

    def has_permission(self, request, view):
        #print(request.user)
        return True
        #return request.user and is_authenticated(request.user)


class IsAuthenticated_2(BasePermission):
    """
    Allows access only to admin users.
    """

    def has_permission(self, request, view):
        #print(request.user)
        return True
        #return request.user and request.user.is_staff


class IsAuthenticated_3(BasePermission):
    """
    The request is authenticated as a user, or is a read-only request.
    """

    def has_permission(self, request, view):
        #print(request.user)
        return True
        #return (
        #    request.method in SAFE_METHODS or
        #    request.user and
        #    is_authenticated(request.user)
        #)