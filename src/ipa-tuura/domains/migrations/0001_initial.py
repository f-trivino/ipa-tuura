# Generated by Django 4.1.5 on 2023-01-13 12:02

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Domain',
            fields=[
                ('name', models.CharField(max_length=80, primary_key=True, serialize=False)),
                ('integration_domain_url', models.CharField(max_length=80)),
                ('client_id', models.CharField(max_length=20)),
                ('client_secret', models.CharField(max_length=20)),
                ('description', models.TextField(blank=True)),
                ('id_provider', models.CharField(choices=[('ipa', 'FreeIPA Provider'), ('ad', 'LDAP AD Provider'), ('ldap', 'LDAP Provider')], default='ipa', max_length=5)),
                ('user_extra_attrs', models.CharField(max_length=100)),
                ('ldap_tls_cacert', models.CharField(max_length=100)),
            ],
        ),
    ]
