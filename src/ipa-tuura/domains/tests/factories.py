from domains.models import Domain
from factory.django import DjangoModelFactory
from faker import Faker


class DomainFactory(DjangoModelFactory):
    print(Faker().locales)
    name = Faker("ipa.test")
    description = Faker("IPA Integration Domain")
    integration_domain_url = Faker("https://master.ipa.test")
    client_id = Faker("admin")
    client_secret = Faker("Secret123")
    id_provider = Faker("ipa")
    user_extra_attrs = Faker("mail:mail, sn:sn, givenname:givenname")
    user_object_classes = Faker("")
    users_dn = Faker("ou=people,dc=ldap,dc=test")
    ldap_tls_cacert = Faker("/etc/openldap/certs/cacert.pem")

    class Meta:
        model = Domain
