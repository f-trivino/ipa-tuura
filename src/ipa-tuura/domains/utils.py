import json
import subprocess
import sys
import SSSDConfig
import warnings
import logging
import subprocess
import socket
import os
import tempfile

from ipalib import api
from ipalib.install.kinit import kinit_password, kinit_keytab
from urllib.parse import urlunparse
from django_scim.settings import scim_settings
from ipalib.facts import is_ipa_client_configured
from urllib.parse import urlparse

from django.conf import settings

logger = logging.getLogger(__name__)


def activate_ifp(sssdconfig):
    """
    Configure the ifp section of sssd.conf

    Activate the ifp service and add the following user_attributes
    to the [ifp] section:
    +mail, +givenname, +sn, +lock

    If the attributes were part of the negative list (for instance
    user_attributes = -givenname), they are removed from the negative list
    and added in the positive list.
    The other attributes are kept.
    """
    try:
        sssdconfig.activate_service('ifp')
        ifp = sssdconfig.get_service('ifp')
    except SSSDConfig.NoServiceError as e:
        print("ifp service not enabled, "
              "ensure the host is properly configured")
        raise e

    # edit the [ifp] section
    try:
        user_attrs = ifp.get_option('user_attributes')
    except SSSDConfig.NoOptionError:
        user_attrs = set()
    else:
        negative_set = {"-mail", "-givenname", "-sn", "-lock"}
        user_attrs = {s.strip() for s in user_attrs.split(',')
                      if s.strip() and s.strip().lower() not in negative_set}

    positive_set = {"+mail", "+givenname", "+sn", "+lock"}
    ifp.set_option('user_attributes',
                   ', '.join(user_attrs.union(positive_set)))
    sssdconfig.save_service(ifp)

def add_sssd_domain(sssdconfig, domain):
    try:
        sssd_domain = sssdconfig.new_domain(domain['integration_domain'])
    except SSSDConfig.DomainAlreadyExistsError:
        logger.info(
            "Domain %s is already configured in existing SSSD "
            "config, creating a new one.",
            domain['integration_domain'])
        logger.info(
            "The old /etc/sssd/sssd.conf is backed up and will be restored "
            "during uninstall.")
        sssdconfig = SSSDConfig.SSSDConfig()
        sssdconfig.new_config()
        sssd_domain = sssdconfig.new_domain(domain['integration_domain'])

    if domain['id_provider'] == 'ad':
        logger.info('AD Provider')
        sssd_domain.add_provider('ad', 'id')
        pass

    elif domain['id_provider'] == 'ldap':
        logger.info('LDAP Provider')
        sssd_domain.add_provider('ldap', 'id')
        pass

    else:
        logger.info('IPA Provider')
        sssd_domain.add_provider('ipa', 'id')
        sssd_domain.set_option('ipa_domain', domain['integration_domain'])

    sssdconfig.save_domain(sssd_domain)



def configure_domain(domain):
    """
    Configure the domain with extra attribute mappings

    Add the following ldap_user_extra_attrs mappings to the [domain/<name>]
    section:
    mail:mail, sn:sn, givenname:givenname
    If the section already defines some mappings, they are kept.
    """
    try:
        extra_attrs = domain.get_option('ldap_user_extra_attrs')
    except SSSDConfig.NoOptionError:
        extra_attrs = set()
    else:
        extra_attrs = {s.strip().lower() for s in extra_attrs.split(',')
                       if s.strip()}

    additional_attrs = {"mail:mail", "sn:sn", "givenname:givenname",
                        "lock:nsaccountlock"}
    domain.set_option('ldap_user_extra_attrs',
                      ", ".join(extra_attrs.union(additional_attrs)))


def configure_domains(sssdconfig, domain):
    """
    Configure the domains with extra attribute mappings

    Loop on the configured domains and configure the domain with extra
    attribute mappings if the id_provider is one of "ipa", "ad", "ldap".
    """
    # Configure each ipa/ad/ldap domain
    domains = sssdconfig.list_active_domains()
    for name in domains:
        domain = sssdconfig.get_domain(name)
        provider = domain.get_option('id_provider')
        if provider in {"ipa", "ad", "ldap"}:
            configure_domain(domain)
            sssdconfig.save_domain(domain)


def customize_sssd(domain):
    try:
        sssdconfig = SSSDConfig.SSSDConfig()
        sssdconfig.import_config()
    except Exception as e:
        # SSSD configuration does not exist or cannot be parsed
        print("Unable to parse SSSD configuration")
        print("Please ensure the host is properly configured.")
        raise e



    # add sssd domain depending on the provider
    # only 1 domain is supported
    # for multidomains go for:
    # configure_domains(sssdconfig, domain)
    add_sssd_domain(sssdconfig, domain)

    # Ensure ifp service is enabled
    # Add attributes to the InfoPipe responder
    activate_ifp(sssdconfig)

    sssdconfig.write()


def install_client(domain):
    """
    :param domain
    """
    args = [
        'ipa-client-install',
        '--domain', domain['integration_domain'],
        '--realm', domain['integration_domain'].upper(),
        '-p', domain['client_id'],
        '-w', domain['client_secret'],
        '-U'
    ]

    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        raise Exception("Error enrolling client:\n{}".format(proc.stderr))

    return proc

def uninstall_client():
    proc = subprocess.run(['ipa-client-install', '--uninstall', '-U'],
                     raiseonerr=False)
    if proc.returncode != 0:
        raise Exception("Error uninstalling client:\n{}".format(proc.stderr))

    return proc

def is_ipa_client_installed(on_master=False):
    """
    Consider IPA client not installed if nothing is backed up
    and default.conf file does not exist. If on_master is set to True,
    the existence of default.conf file is not taken into consideration,
    since it has been already created by ipa-server-install.
    """
    warnings.warn(
	"Use 'ipalib.facts.is_ipa_client_configured'",
        DeprecationWarning,
	stacklevel=2
    )
    return is_ipa_client_configured(on_master)

def restart_sssd():
    args = ["systemctl", "restart", "sssd"]
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        raise Exception("Error restarting SSSD:\n{}".format(proc.stderr))

def list_domains():
    """
    Return a list of active domains
    """
    try:
        sssdconfig = SSSDConfig.SSSDConfig()
        sssdconfig.import_config()
    except Exception as e:
        # SSSD configuration does not exist or cannot be parsed
        print("Unable to parse SSSD configuration")
        print("Please ensure the host is properly configured.")
        raise e

    domains = sssdconfig.list_active_domains()
    return domains

def api_connect(domain):
    backend = None
    context = "client"
    ccache_dir = tempfile.mkdtemp(prefix='krbcc')
    ccache_name = os.path.join(ccache_dir, 'ccache')

    base_config = dict(
        context=context, in_server=False, debug=False
    )


    # kinit with user
    try:
        kinit_password(domain['admin'], domain['password'], ccache_name)
    except RuntimeError as e:
        raise RuntimeError("Kerberos authentication failed: {}".format(e))

    # init IPA API
    try:
        api.bootstrap(**base_config)
        if not api.isdone("finalize"):
            api.finalize()
    except Exception as e:
        logger.info(f'bootstrap already done {e}')

    backend = api.Backend.rpcclient
    if not backend.isconnected():
        backend.connect(ccache=os.environ.get('KRB5CCNAME', None))


def deploy_service(domain):
    hostname = socket.gethostname()
    realm = 'TESTREALM.TEST'
    ipatuura_wiface = 'ipatuura/%s@%s' % (hostname, realm)
    keytab_file = os.path.join('/var/lib/ipa/ipatuura/', 'service.keytab')
    api_connect(domain)

    # this is supposed to be there already
    # useradd -r -m -d /var/lib/ipa/ipatuura -g scim

    # add service
    result = api.Command['service_add'](krbcanonicalname=ipatuura_wiface)
    # logger.info(f'ipa user_add result {result}')


    # add role-add-member
    result = api.Command['role_add_member'](
        cn='ipatuura writable interface',
        service=ipatuura_wiface
    )

    # get keytab
    args = ['ipa-getkeytab', '-p', ipatuura_wiface, '-k', keytab_file]
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        raise Exception("Error getkeytab:\n{}".format(proc.stderr))

    os.system('chown -R keycloak:keycloak /var/lib/ipa/ipatuura/')
    
    # add service
    args = ['ipa', 'service-add', ipatuura_wiface]
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        raise Exception("Error service-add:\n{}".format(proc.stderr))

    # add role-add-member
    args = ['ipa', 'role-add-member', 'ipatuura writable interface', '--service', ipatuura_wiface]
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        raise Exception("Error role-add-member:\n{}".format(proc.stderr))

    # get keytab
    args = ['ipa-getkeytab', '-p', ipatuura_wiface, '-k', keytab_file]
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        raise Exception("Error getkeytab:\n{}".format(proc.stderr))


def undeploy_service(domain):
    hostname = socket.gethostname()
    realm = 'TESTREALM.TEST'
    ipatuura_wiface = 'ipatuura/%s@%s' % (hostname, realm)
    keytab_file = os.path.join('/var/lib/ipa/ipatuura/', 'service.keytab')

    api_connect(domain)

    # remove keytab
    # role-add-remove
    # service-delete


def remove_sssd_domain():
    try:
        sssdconfig = SSSDConfig.SSSDConfig()
        sssdconfig.import_config()
        domains = sssdconfig.list_active_domains()

        ipa_domain_name = None

        for name in domains:
            domain = sssdconfig.get_domain(name)
            try:
                provider = domain.get_option('id_provider')
                if provider == "ipa":
                    ipa_domain_name = name
                    break
            except SSSDConfig.NoOptionError:
                continue

        if ipa_domain_name is not None:
            sssdconfig.delete_domain(ipa_domain_name)
            sssdconfig.write()
        else:
            logger.info('IPA domain could not be found in /etc/sssd/sssd.conf and therefore not deleted')
    except IOError:
        logger.info('IPA domain could not be deleted. No access to the /etc/sssd/sssd.conf file.')


def configure_ipatuura(id_provider):
    # configure root/settings so that the writable
    # interface can use the integration domain
    
    settings.SCIM_SERVICE_PROVIDER['WRITABLE_IFACE']



def add_domain(domain):
    """
    Add a domain with extra attribute mappings
    
    Enroll ipa-tuura as an IPA client to the new domain

    Add the following ldap_user_extra_attrs mappings to the [domain/<name>]
    section:
    mail:mail, sn:sn, givenname:givenname
    """

    # NB!! only single domain is supported
    # TODO: input validation of domain content
    # TODO: check if there is a domain already configured
    install_client(domain)

    # tune sssd.conf
    # add attrs to infopipe
    customize_sssd(domain)

    # apply changes
    # I don't know how to do this in the container
    restart_sssd()

    # configure ipatuura writable interface
    # deploy service for the writable interface
    deploy_service(domain)

    # configure ipatuura writable interface
    configure_ipatuura(domain['id_provider'])



def delete_domain(domain):
    """Helper function for uninstall.
    Deletes IPA domain from sssd.conf
    """
    # remove the service account
    # this is for AD and IPA providers.
    undeploy_service(domain)

    # ipa client uninstall moves the sssd.conf to sssd.conf.deleted
    uninstall_client()

    # for multidomain go for:
    # remove_sssd_domain()
