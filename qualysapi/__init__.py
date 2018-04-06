# This is the version string assigned to the entire egg post
# setup.py install

# Ownership and Copyright Information.
from __future__ import absolute_import
__author__ = "Parag Baxi <parag.baxi@gmail.com>"
__copyright__ = "Copyright 2011-2013, Parag Baxi"
__license__ = "BSD-new"

<<<<<<< HEAD

import logging

import qualysapi.config as qcconf
import qualysapi.connector as qcconn
import qualysapi.settings as qcs


def connect(**kwargs):

    defaults = {
        'config_file'        : qcs.default_filename,
        'remember_me'        : False,
        'remember_me_always' : False
    }
    defaults.update(kwargs)

    """ Return a QGAPIConnect object for v1 API pulling settings from config
    file.
    """
    # Retrieve login credentials.
    conf = kwargs.get(
            'config',
            qcconf.QualysConnectConfig(**defaults))
    connect = qcconn.QGConnector(
            conf.get_auth(),
            hostname=conf.get_hostname(),
            proxies=conf.proxies,
            max_retries=conf.max_retries,
            config=conf)
    logging.info("Finished building connector.")
    return connect
||||||| merged common ancestors
from qualysapi.util import connect
=======
from qualysapi.util import connect
>>>>>>> bd8eac49447bb49fa3128d365076786daf923b4a
