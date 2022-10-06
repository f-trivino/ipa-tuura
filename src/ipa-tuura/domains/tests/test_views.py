from django.test import TestCase
from django.urls import reverse
from domains.tests.factories import DomainFactory
from rest_framework import status


class DomainViewSetTestCase(TestCase):
    def setUp(self):
        self.domain = DomainFactory(name="ipa.test")
        self.domain = DomainFactory(description="IPA Integration Domain")
        self.domain = DomainFactory(integration_domain_url="https://master.ipa.test")
        self.domain = DomainFactory(client_id="admin")
        self.domain = DomainFactory(client_secret="Secret123")
        self.domain = DomainFactory(id_provider="ipa")
        self.domain = DomainFactory(
            user_extra_attrs="mail:mail, sn:sn, givenname:givenname"
        )
        self.domain = DomainFactory(user_object_classes="")
        self.domain = DomainFactory(users_dn="ou=people,dc=ldap,dc=test")
        self.domain = DomainFactory(ldap_tls_cacert="/etc/openldap/certs/cacert.pem")
        self.domain.save()
        self.list_url = reverse("domain-list")

    def test_domain_list_view(self):
        """GET the list page of Domains"""
        resp = self.client.get(self.list_url)

        self.assertEqual(resp.status_code, 200)
        self.assertIn(domain.name.encode(), resp.content)

    def test_get_list(self):
        """GET the list page of Domains"""
        domains = [DomainFactory() for i in range(0, 3)]

        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            set(domain["id"] for domain in response.data["results"]),
            set(domain.id for domain in domains),
        )






    def get_detail_url(self, domain_id):
        return reverse(self.domain_detail, kwargs={"id": domain_id})

    def test_get_detail(self):
        """GET a detail page for a Domain."""
        domain = DomainFactory()
        response = self.client.get(self.get_detail_url(domain.id))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["name"], domain.name)

    def test_post(self):
        """POST to create a Domain."""
        data = {
            "name": "ipa.test",
            "description": "IPA Integration Domain",
            "integration_domain_url": "https://master.ipa.test",
            "client_id": "admin",
            "client_secret": "Secret123",
            "id_provider": "ipa",
            "user_extra_attrs": "mail:mail, sn:sn, givenname:givenname",
            "user_object_classes": "",
            "users_dn": "ou=people,dc=ldap,dc=test",
            "ldap_tls_cacert": "/etc/openldap/certs/cacert.pem",
        }
        self.assertEqual(self.domain.objects.count(), 0)
        response = self.client.post(self.list_url, data=data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(self.domain.objects.count(), 1)
        domain = self.domain.objects.all().first()
        for field_name in data.keys():
            self.assertEqual(getattr(domain, field_name), data[field_name])

    def test_put(self):
        """PUT to update a Domain."""
        domain = DomainFactory()
        data = {
            "name": "ipa.test",
            "description": "IPA Integration Domain",
            "integration_domain_url": "https://master.ipa.test",
            "client_id": "admin",
            "client_secret": "Secret123",
            "id_provider": "ipa",
            "user_extra_attrs": "mail:mail, sn:sn, givenname:givenname",
            "user_object_classes": "",
            "users_dn": "ou=people,dc=ldap,dc=test",
            "ldap_tls_cacert": "/etc/openldap/certs/cacert.pem",
        }
        response = self.client.put(self.get_detail_url(domain.id), data=data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # The object has really been updated
        domain.refresh_from_db()
        for field_name in data.keys():
            self.assertEqual(getattr(domain, field_name), data[field_name])

    def test_patch(self):
        """PATCH to update a Domain."""
        domain = DomainFactory()
        data = {"name": "LDAP Integration Domain"}
        response = self.client.patch(self.get_detail_url(domain.id), data=data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # The object has really been updated
        domain.refresh_from_db()
        self.assertEqual(domain.name, data["name"])

    def test_delete(self):
        domain = DomainFactory()
        response = self.client.delete(self.get_detail_url(domain.id))
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
