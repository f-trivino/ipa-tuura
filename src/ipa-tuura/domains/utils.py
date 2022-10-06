#
# Copyright (C) 2023  FreeIPA Contributors see COPYING for license
#

import SSSDConfig
import logging
import subprocess
import socket
import os
import tempfile

from ipalib import api

logger = logging.getLogger(__name__)


def kinit_password(principal, password, ccache_name):
    """
    Perform kinit using principal/password.
    It uses the specified config file to kinit and stores the TGT
    in ccache_name.
    """
    args = ["/usr/bin/kinit", principal, '-c', ccache_name]

    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        raise Exception("Error kinit_password:\n{}".format(proc.stderr))


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
    # hardcoded to "+mail, +givenname, +sn, +lock" for now
    # TODO: read content from domain['user_extra_attrs']
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
        sssd_domain = sssdconfig.new_domain(domain['name'])
    except SSSDConfig.DomainAlreadyExistsError:
        logger.info(
            "Domain %s is already configured in existing SSSD "
            "config, creating a new one.",
            domain['name'])
        logger.info(
            "The old /etc/sssd/sssd.conf is backed up and will be restored "
            "during uninstall.")
        sssdconfig = SSSDConfig.SSSDConfig()
        sssdconfig.new_config()
        sssd_domain = sssdconfig.new_domain(domain['name'])

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
        sssd_domain.set_option('ipa_domain', domain['name'])

    sssdconfig.save_domain(sssd_domain)


def customize_sssd(domain):
    """
    Add the following ldap_user_extra_attrs mappings to the [domain/<name>]
    section: mail:mail, sn:sn, givenname:givenname
    """
    try:
        sssdconfig = SSSDConfig.SSSDConfig()
        sssdconfig.import_config()
    except Exception as e:
        # At initial startup, there is no domain and no sssd config
        logger.info('Unable to read SSSD config')
        pass

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
        '--domain', domain['name'],
        '--realm', domain['name'].upper(),
        '-p', domain['client_id'],
        '-w', domain['client_secret'],
        '-U'
    ]

    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        raise Exception("Error enrolling client:\n{}".format(proc.stderr))

    return proc


def uninstall_ipa_client():
    proc = subprocess.run(
        ['ipa-client-install', '--uninstall', '-U'],
        raiseonerr=False
        )
    if proc.returncode != 0:
        raise Exception("Error uninstalling client:\n{}".format(proc.stderr))

    return proc


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


def ipa_api_connect(domain):
    backend = None
    context = "client"
    ccache_dir = tempfile.mkdtemp(prefix='krbcc')
    ccache_name = os.path.join(ccache_dir, 'ccache')

    base_config = dict(
        context=context, in_server=False, debug=False
    )

    # kinit with user
    try:
        kinit_password(
            domain['client_id'],
            domain['client_secret'],
            ccache_name
            )
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


def undeploy_ipa_service(domain):
    hostname = socket.gethostname()
    realm = domain['name'].upper()
    ipatuura_principal = 'ipatuura/%s@%s' % (hostname, realm)
    keytab_file = os.path.join('/var/lib/ipa/ipatuura/', 'service.keytab')
    ipa_api_connect(domain)

    # remove keytab
    args = ['ipa-rmkeytab', '-p', ipatuura_principal, '-k', keytab_file]
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        raise Exception("Error rmkeytab:\n{}".format(proc.stderr))

    # role-remove
    args = ['ipa',
            'role-remove-member',
            'ipatuura writable interface',
            '--service',
            ipatuura_principal]

    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        raise Exception("Error role-remove-member:\n{}".format(proc.stderr))

    # service-delete
    args = ['ipa', 'service-remove', ipatuura_principal]
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        raise Exception("Error service-remove:\n{}".format(proc.stderr))


def deploy_ipa_service(domain):
    hostname = socket.gethostname()
    realm = domain['name'].upper()
    ipatuura_principal = 'ipatuura/%s@%s' % (hostname, realm)
    keytab_file = os.path.join('/var/lib/ipa/ipatuura/', 'service.keytab')
    ipa_api_connect(domain)

    # this is supposed to be there already
    # useradd -r -m -d /var/lib/ipa/ipatuura -g scim

    # add service
    result = api.Command['service_add'](krbcanonicalname=ipatuura_principal)

    # add role-add-member
    result = api.Command['role_add_member'](
        cn='ipatuura writable interface',
        service=ipatuura_principal
    )

    logger.info(f'ipa: service_add result {result}')

    # get keytab
    args = ['ipa-getkeytab', '-p', ipatuura_principal, '-k', keytab_file]
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        raise Exception("Error getkeytab:\n{}".format(proc.stderr))

    os.system('chown -R keycloak:keycloak /var/lib/ipa/ipatuura/')

    # add service
    args = ['ipa', 'service-add', ipatuura_principal]
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        raise Exception("Error service-add:\n{}".format(proc.stderr))

    # add role-add-member
    args = ['ipa',
            'role-add-member',
            'ipatuura writable interface',
            '--service',
            ipatuura_principal]

    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        raise Exception("Error role-add-member:\n{}".format(proc.stderr))

    # get keytab
    args = ['ipa-getkeytab', '-p', ipatuura_principal, '-k', keytab_file]
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        raise Exception("Error getkeytab:\n{}".format(proc.stderr))


def remove_sssd_domain(domain):
    try:
        sssdconfig = SSSDConfig.SSSDConfig()
        sssdconfig.import_config()
        domains = sssdconfig.list_active_domains()

        domain_name = None

        for name in domains:
            if name == domain['name']:
                domain_name = name
                break

        if domain_name is not None:
            sssdconfig.delete_domain(domain_name)
            sssdconfig.write()
        else:
            logger.info(
                "IPA domain could not be found in /etc/sssd/sssd.conf "
                " and therefore not deleted"
                )
    except IOError:
        logger.info(
            "IPA domain could not be deleted. "
            "No access to the /etc/sssd/sssd.conf file."
            )


def configure_ipatuura(id_provider):
    # configure root/settings so that the writable
    # interface can use the integration domain

    # TBD: implement is_active domain
    # django settings are immutable
    pass


def add_domain(domain):
    """
    Add an integration domain with extra attribute mappings

    Supported identity providers: ipa, ldap, and ad.
    """
    # Enroll ipa-tuura as an IPA client to the new domain
    if domain['id_provider'] == 'ipa':
        # TODO: check if ipa client is installed
        install_client(domain)
        deploy_ipa_service(domain)

    # customize sssd.conf file with extra attribute mappings
    customize_sssd(domain)
    restart_sssd()

    # configure ipatuura writable interface
    configure_ipatuura(domain['id_provider'])


def delete_domain(domain):
    """
    Delete an integration domain
    """
    if domain['id_provider'] == 'ipa':
        # undeploy the service account
        undeploy_ipa_service(domain)

        # ipa client uninstall moves the sssd.conf to sssd.conf.deleted
        uninstall_ipa_client()
        return

    # LDAP (ad, ldap): remove domian from sssd.conf
    # TODO: undeploy LDAP service account
    remove_sssd_domain(domain)
    restart_sssd()


def update_domain(domain):
    """
    Update an integration domain

    Supported identity providers: ipa, ldap, and ad.
    """
    pass
