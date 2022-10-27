import json
import subprocess
import sys
import SSSDConfig

from urllib.parse import urlunparse
from django_scim.settings import scim_settings



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

def add_domain(domain):
    """
    Add a domain with extra attribute mappings

    Enroll ipa-tuura as an IPA client to the new domain

    Add the following ldap_user_extra_attrs mappings to the [domain/<name>]
    section:
    mail:mail, sn:sn, givenname:givenname
    """

    # TODO: input validation of domain content
    # TODO: check if the domain exists
    # TODO: enroll to the domain
    # TODO: add mandatory attributes

def delete_ipa_domain():
    """Helper function for uninstall.
       Deletes IPA domain from sssd.conf
    """
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
            logger.warning(
                "IPA domain could not be found in "
                "/etc/sssd/sssd.conf and therefore not deleted")
    except IOError:
        logger.warning(
            "IPA domain could not be deleted. "
            "No access to the /etc/sssd/sssd.conf file.")
