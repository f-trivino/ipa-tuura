from django.test import TestCase

from domains.models import Domain
from domains.tests.factories import DomainFactory


class DomainTestCase(TestCase):
    def test_str(self):
        """Test for string representation."""
        domain = DomainFactory()
        self.assertEqual(str(domain), domain.name)






from django.urls import reverse

# models test
class DomainTest(TestCase):

    def create_domain(self, name="domain.test", description="yes, this is only a test"):
        return Domain.objects.create(name=name, description=description)

    def test_domain_creation(self):
        w = self.create_domain()
        self.assertTrue(isinstance(w, Domain))

    def test_domain_list_view(self):
        domain = self.create_domain()
        url = reverse("domain-list")
        resp = self.client.get(url)

        self.assertEqual(resp.status_code, 200)
        self.assertIn(domain.name.encode(), resp.content)

