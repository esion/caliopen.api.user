# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging

from .security import AuthenticationPolicy, AuthorizationPolicy

log = logging.getLogger(__name__)


def includeme(config):
    """Configure REST API for user and contact."""
    config.set_authentication_policy(AuthenticationPolicy())
    config.set_authorization_policy(AuthorizationPolicy())
    log.debug('Loading user API')
    config.scan('caliopen.api.user.user')

    log.debug('Loading contact API')
    config.scan('caliopen.api.user.contact')
