# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging
import base64

from zope.interface import implements, implementer
from pyramid.interfaces import IAuthenticationPolicy, IAuthorizationPolicy
from pyramid.security import Everyone, NO_PERMISSION_REQUIRED


from caliopen.base.user.core import User

log = logging.getLogger(__name__)


class _NotAuthenticated(Exception):

    """Raised when the authenticated user cannot be built."""


class AuthenticatedUser(object):

    """Represent an authenticated user."""

    def __init__(self, request):
        if 'Authorization' not in request.headers:
            raise _NotAuthenticated

        authorization = request.headers['Authorization'].split()
        if authorization[0] != 'Bearer' and len(authorization) != 2:
            raise _NotAuthenticated

        log.debug('Authentication via Access Token')
        auth = base64.decodestring(authorization[1])
        # authentication values is user_id:token
        if ':' not in auth:
            raise _NotAuthenticated

        user_id, token = auth.split(':')
        infos = request.cache.get(user_id)
        if infos.get('access_token') != token:
            raise _NotAuthenticated

        self.user_id = user_id
        self.access_token = token
        self._user = None

    def _load_user(self):
        if self._user:
            return
        self._user = User.get(self.user_id)

    @property
    def id(self):
        self._load_user()
        return self._user.user_id

    @property
    def username(self):
        self._load_user()
        return self._user.name


class AuthenticationPolicy(object):

    """Global authentication policy."""

    implements(IAuthenticationPolicy)

    def authenticated_userid(self, request):
        if hasattr(request, '_CaliopenUser'):
            return request._CaliopenUser

        try:
            request._CaliopenUser = AuthenticatedUser(request)
        except _NotAuthenticated:
            return None

        return request._CaliopenUser

    def effective_principals(self, request):
        account = self.authenticated_userid(request)
        if not account:
            return [Everyone]
        return ["%s:%s" % (account.user_id, account.access_token)]

    def unauthenticated_userid(self, request):
        try:
            return AuthenticatedUser(request)
        except _NotAuthenticated:
            return None

    def remember(self, request, principal, **kw):
        """Token Key mechanism can't remember anyone."""
        return []

    def forget(self, request):
        return [('WWW-Authenticate', 'Bearer realm="Caliopen"')]


@implementer(IAuthorizationPolicy)
class AuthorizationPolicy(object):

    """Basic authorization policy."""

    def permits(self, context, principals, permission):
        """ Return an instance of
        :class:`pyramid.security.ACLAllowed` instance if the policy
        permits access, return an instance of
        :class:`pyramid.security.ACLDenied` if not."""
        if permission == NO_PERMISSION_REQUIRED:
            return True

        if not principals:
            False

        token = principals[0]
        if ':' in token and permission == 'authenticated':
            # All managed objects belong to authenticated user
            # no other policy to apply
            return True
        return False

    def principals_allowed_by_permission(self, context, permission):
        raise NotImplementedError
