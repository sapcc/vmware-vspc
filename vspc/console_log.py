import os
import base64
from functools import wraps
from flask import Flask
from flask import request, Response

from oslo_config import cfg
from oslo_log import log as logging

opts = [
    cfg.StrOpt('host',
               default='0.0.0.0',
               help='Host on which to listen for incoming requests'),
    cfg.IntOpt('port',
               default=13370,
               help='Port on which to listen for incoming requests'),
    cfg.StrOpt('cert', help='SSL certificate file'),
    cfg.StrOpt('key', help='SSL key file (if separate from cert)'),
    cfg.StrOpt('uri', help='VSPC URI'),
    cfg.StrOpt('serial_log_dir', help='The directory where serial logs are '
                                      'saved'),
    cfg.StrOpt('username', default="admin", help='The directory where serial logs are '
                                          'saved'),
    cfg.StrOpt('password', default="secret", help='The directory where serial logs are '
                                          'saved'),
]

CONF = cfg.CONF
CONF.register_opts(opts)

LOG = logging.getLogger(__name__)

app = Flask(__name__)


def check_auth(username, password):
    """This function is called to check if a username /
    password combination is valid.
    """
    return username == CONF.username and password == CONF.password


def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization

        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)

    return decorated

@app.route("/console_log/<uuid>")
@requires_auth
def retrieve_console_log(uuid):
    """ The endpoint serves for retrieving the log from the instance outputed in the log directory
        every log is identified by the instance uuid
    """
    uuid = uuid.replace(' ', '')
    uuid = uuid.replace('-', '')
    LOG.info('Opening %s for reading console logs.', "/opt/stack/vspc/")
    LOG.info('Reading file %s ...', uuid)
    file_path = "/opt/vmware/vspc/" + uuid

    if os.path.isfile(file_path) is False:
        LOG.error('File path %s not found!', file_path)
        return Response(
            'Could not find the requested resource.', 401)

    if uuid is None:
        LOG.error("UUID was not set! UUID - %s", uuid)
        return

    file = open(file_path, 'rb')
    file_content = file.read()
    file.close()

    return file_content

app.run(port=13372)

if __name__ == 'main':
    app.run()