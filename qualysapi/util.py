""" A set of utility functions for QualysConnect module. """
from __future__ import absolute_import
import logging

__author__ = "Parag Baxi <parag.baxi@gmail.com> & Colin Bell <colin.bell@uwaterloo.ca>"
__copyright__ = "Copyright 2011-2013, Parag Baxi & University of Waterloo"
__license__ = 'Apache License 2.0'

# Set module level logger.
logger = logging.getLogger(__name__)


def preformat_call(api_call):
    """ Return properly formatted QualysGuard API call.

    """
<<<<<<< HEAD
    # Remove possible starting slashes or trailing question marks in call.
    api_call_formatted = api_call.lstrip('/')
    api_call_formatted = api_call_formatted.rstrip('?')
    if api_call != api_call_formatted:
        # Show difference
        logger.debug('api_call post strip =\n%s' % api_call_formatted)
    return api_call_formatted
||||||| merged common ancestors
    # Retrieve login credentials.
    conf = qcconf.QualysConnectConfig(filename=config_file, remember_me=remember_me,
                                      remember_me_always=remember_me_always)
    connect = qcconn.QGConnector(conf.get_auth(),
                                 conf.get_hostname(),
                                 conf.proxies,
                                 conf.max_retries)
    logger.info("Finished building connector.")
    return connect
=======
    # Retrieve login credentials.
    conf = qcconf.QualysConnectConfig(filename=config_file, remember_me=remember_me,
                                      remember_me_always=remember_me_always)
    connect = qcconn.QGConnector(conf.get_auth(),
                                 conf.get_hostname(),
                                 conf.proxies,
                                 conf.max_retries)
    logger.info("Finished building connector.")
    return connect
>>>>>>> bd8eac49447bb49fa3128d365076786daf923b4a
