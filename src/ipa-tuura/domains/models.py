import logging

from django.db import models


logger = logging.getLogger(__name__)


class Domain(models.Model):
    """
    Integration Domain model.
    This defines an integration domain supported by ipatuura service.
    The fields corresponds to the integration domain required
    configuration fields.
    """

    # Field Choices for the supported integration domain provider types
    DOMAIN_PROVIDER_TYPE = (
        ('ipa', _('FreeIPA Provider')),
        ('ad', _('LDAP AD Provider')),
        ('ldap', _('LDAP Provider')),
    )

    # The connection URL to the identity server
    integration_domain_url = models.CharField(primary_key=True, max_length=80)

    # Temporary admin service username
    client_id = models.CharField(max_length=20)

    # Temporary admin service password
    client_secret = models.CharField(max_length=20)

    # Optional description
    description = models.TextField(blank=True)

    # Identity provider type
    id_provider = models.CharField(
        max_length=5,
        choices=DOMAIN_PROVIDER_TYPE,
        default='ipa',
    )

    # LDAP auth with TLS support, ipa-tuura needs to fetch the CA certificate file
    # that is configured on the AD/LDAP server before proceeding...
    ldap_tls_cacert = models.CharField(max_length=100)

    def __str__(self):
        return self.name
