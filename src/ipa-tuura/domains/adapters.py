import logging

from rest_framework.serializers import ModelSerializer

from domains.models import Domain


logger = logging.getLogger(__name__)


class DomainSerializer(ModelSerializer):
    class Meta:
        model = Domain
        fields = (
            'integration_domain_url',
            'client_id',
            'client_secret',
            'description',
            'id_provider',
            'ldap_tls_cacert',
        )
