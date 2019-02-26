#!/usr/bin/python

# Copyright: (c) 2018, NETSCOUT.
# GNU General Public License v3.0+ (see COPYING or  https://www.gnu.org/licenses/gpl-3.0.txt) noqa


from contextlib import contextmanager
from ansible.module_utils.connection import ConnectionError

_DEVICE_CONNECTION = None
"""XXX: I don't think this is used anywhere"""
AED_API_LOGIN_FORM = "/platform/login"
"""XXX: I don't think this is used anywhere"""
AED_API_AUTH_COOKIE_NAME = "auth_tkt"
"""XXX: I don't think this is used anywhere"""
AED_DEFAULT_API_VERSION = 2
"""XXX: I don't think this is used anywhere"""
AED_API_PATH_FMT = "/api/aed/v{0}"
"""XXX: I don't think this is used anywhere"""
aed_provider_spec = {}  # If need to build default args
"""XXX: I don't think this is used anywhere"""
aed_argument_spec = {}  # If need to build default args
"""TODO: Description of this attribute"""


class AEDAPIError(Exception):
    """Raised when an error occurs while sending an API request"""
    pass


class ResponseCodes(object):
    """Enum class describing HTTP responses to API requests."""

    GOOD_RESP = [200, 201, 202]
    """list(int): HTTP response codes indicating a successful request."""
    REDIR_RESP = [301, 302]
    """list(int): HTTP response codes indicating a redirect is necessary."""
    GOOD_DEL_RESP = [204]
    """list(int): HTTP response codes indicating a successful DEL request."""


def check_args(module, warnings):
    """Perform a sanity check on the parameters passed to a module.

    This method should be called prior to using the parameters that are passed
    to the module via the JSON file given as the first command-line argument.

    If any warnings are raised, they should be appended to the ``warnings``
    argument.
    If any fatal errors are raised, this function should call
    ``module.fail_json()``.

    XXX: I don't think this should be a global method, since each module is
    going to have a unqiue set of parameters, and it is unlikely that there
    will be a 'common' set of parameters to check.
    """
    pass


class AEDAPIBase(object):
    """High-level wrapper around the AED httpapi connection plugin.

    Provides CRUD-like access to API endpoints.

    XXX: The ``*_config`` methods do not do any error-handling whatsoever; the
    caller must do all of the error handling.
    """
    def __init__(self, conn):
        """Default constructor.

        Args:
            conn (ansible.plugins.connection.httpapi.Connection): httpapi
                connection to AED.
        """
        self._conn = conn
        """
        httpapi connection to AED.
        """
        self.config_changed = False
        """XXX: I don't think this is used anywhere."""

    def send_api_request(
        self, url_path, http_method, body_params=None,
            path_params=None, query_params=None):
        """Send a REST API request to the AED appliance.

        Mostly a thin wrapper around the ``aed.HttpApi.send_request()`` method.

        Args:
            url_path (str): Relative URL to send request to. This is everything
                past the initial ``/api/aed/{version}``. Can be a format-style
                string when combined with the ``path_params`` kwarg.
            http_method (str): HTTP method to use in the request.
            body_params (dict): Python object to use for the request body.
                Must be JSON serializable.
            path_params (dict): Dict of values to insert into the ``url_path``
                using ``format()``-style substitution.
            query_params (dict): Dict of key/value pairs to include in the
                query of the URL.
        Returns:
            dict: Dict consisting of:
                * ``success``: ``True`` if the request succeeded, ``False``
                  otherwise.
                * ``status_code``: HTTP status code as an integer.
                * ``response``: The body of the response as a python dict.
        Raises:
            AEDAPIError: If the ``aed.HttpApi.send_request()`` method
                encounters a connection error.
        """
        try:
            return(
                self._conn.send_request(
                    url_path, http_method, body_params,
                    path_params, query_params
                )
            )
        except ConnectionError as e:
            raise AEDAPIError(e.message)

    def create_config(self, command, body_params=None):
        """Make a POST request to the AED appliance.

        Args:
            command (str): Relative URL path to send request to.
            body_params (dict): Dict to use for the body of the request.
        Returns:
            Tuple consisting of the HTTP status code and the body of the
            response as a python dict.
        """
        resp = self.send_api_request(
            url_path=command,
            http_method='POST',
            body_params=body_params
        )

        return resp.get('status_code'), resp.get('response')

    def delete_config(self, command):
        """Make a DEL request to the AED appliance.

        Args:
            command (str): Relative URL path to send request to.
        Returns:
            Tuple consisting of the HTTP status code and the body of the
            response as a python dict.
        """
        resp = self.send_api_request(
            url_path=command,
            http_method='DELETE',
        )

        return resp.get('status_code'), resp.get('response')

    def get_config(self, command, query_params=None):
        """Make a GET request to the AED appliance.

        Args:
            command (str): Relative URL path to send request to.
            query_params (dict): Dict of key/value pairs to include as .
        Returns:
            Tuple consisting of the HTTP status code and the body of the
            response as a python dict.
        """
        resp = self.send_api_request(
            url_path=command,
            http_method='GET',
            query_params=query_params
        )

        return resp.get('status_code'), resp.get('response')

    def push_config(self, command, body_params=None):
        """Make a PATCH request to the AED appliance.

        Args:
            command (str): Relative URL path to send request to.
            body_params (dict): Dict to use for the body of the request.
        Returns:
            Tuple consisting of the HTTP status code and the body of the
            response as a python dict.
        """
        resp = self.send_api_request(
            url_path=command,
            http_method='PATCH',
            body_params=body_params
        )

        return resp.get('status_code'), resp.get('response')

    def put_config(self, command, body_params=None):
        """Make a PUT request to the AED appliance.

        Args:
            command (str): Relative URL path to send request to.
            body_params (dict): Dict to use for the body of the request.
        Returns:
            Tuple consisting of the HTTP status code and the body of the
            response as a python dict.
        """
        resp = self.send_api_request(
            url_path=command,
            http_method='PUT',
            body_params=body_params
        )

        return resp.get('status_code'), resp.get('response')


def ans_to_rest(ans_dict, param_map):
    """TODO: Description of this method."""
    rest_dict = dict()
    for ans_key, rest_key, func in param_map:
        val = ans_dict.get(ans_key, None)
        if val is not None:
            if func:
                val = func(val)
            rest_dict[rest_key] = val

    return rest_dict


def get_changes(have, want):
    """Crude diffing algorithm for module parameters.

    NOTE: This will only work with dicts that have simple values which define
    equality, i.e. - values that are lists or dicts will not work.

    Args:
        have (dict): Dict representing the current state of the module
            parameters.
        want (dict): Dict representing desired final state of the module
            parameters.
    Returns:
        Dict containing the keys in ``want`` which differ from those in
        ``have``. Values are the values in ``want``.
    """
    changes = dict()
    for key in want:
        if want[key] != have[key]:
            changes[key] = want[key]

    return changes


def rest_to_ans(rest_dict, param_map):
    """TODO: Description of this method."""
    ans_dict = dict()
    for ans_key, rest_key, func in param_map:
        val = rest_dict.get(rest_key, None)
        if val is not None:
            if func:
                val = func(val)

        ans_dict[ans_key] = val

    return ans_dict


def get_want(module, param_map):
    """
    TODO: Description of this method.

    Args:
        module (AnsibleModule): AnsibleModule instance
        param_map (list): list of tuples of ANSIBLE params, rest params and
            mutation method
    Returns:
        dict: Dict of expected configuration
    """
    param_list = [param[0] for param in param_map]

    wanted = {
        key: module.params[key] for key in param_list if
        module.params.get(key, None) is not None
    }

    return wanted


@contextmanager
def exception_context(module, *exceptions):
    """
    Use this context when calling methods in AEDAPIBase
    from the module. Should be ideally used in the main()
    function right after AnsibleModule has been
    initialized.

    Args:
        module (AnsibleModule): AnsibleModule object
        exceptions: exceptions to catch
    Returns:
        A clean error response without traceback information.
    """
    try:
        yield
    except exceptions as e:
        module.fail_json(msg=e.message)
