#
# Copyright (C) 2023  FreeIPA Contributors see COPYING for license
#

import logging

from django.db import models
from django.utils.translation import gettext as _


logger = logging.getLogger(__name__)


class Domain(models.Model):
    """
    Integration Domain model.
    This defines an integration domain supported by ipatuura service.
    The fields corresponds to the integration domain required
    configuration fields.
    """
    # Field Choices for the supported integration domain provider types
    class DomainProviderType(models.TextChoices):
        IPA = 'ipa', _("IPA Provider")
        AD = 'ad', _("LDAP Active Directory Provider")
        LDAP = 'ldap', _("LDAP Provider")

    # TODO: multi-domain, implement is_active boolean flag
    # it designates whether the integration domain should be considered active
    # is_active = models.BooleanField(verbose_name='is active?', default=True)

    # Domain Name
    name = models.CharField(primary_key=True, max_length=80)

    # The connection URL to the identity server
    integration_domain_url = models.CharField(max_length=255)

    # Temporary admin service username
    client_id = models.CharField(max_length=20)

    # Temporary admin service password
    client_secret = models.CharField(max_length=20)

    # Optional description
    description = models.TextField(blank=True)

    # Identity provider type
    id_provider = models.CharField(
        max_length=5,
        choices=DomainProviderType.choices,
        default=DomainProviderType.IPA,
    )

    # Comma-separated list of LDAP attributes that SSSD would
    # fetch along with the usual set of user attributes
    user_extra_attrs = models.CharField(max_length=100)

    # LDAP auth with TLS support, ipa-tuura needs to fetch the CA certificate
    # that is configured on the AD/LDAP server before proceeding
    ldap_tls_cacert = models.CharField(max_length=100)

    def __str__(self):
        return self.name
