#
# Copyright (C) 2023  FreeIPA Contributors see COPYING for license
#

import logging

from rest_framework.serializers import ModelSerializer

from domains.models import Domain


logger = logging.getLogger(__name__)


class DomainSerializer(ModelSerializer):
    class Meta:
        model = Domain
        fields = (
            'name',
            'integration_domain_url',
            'client_id',
            'client_secret',
            'description',
            'id_provider',
            'user_extra_attrs',
            'ldap_tls_cacert',
        )
