# (c) 2018 Red Hat Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
---
author: chartmann
httpapi : aed
short_description: The HttpApi plugin for AED devices
description:
  - This HttpApi plugin provides the methods to connect to AED
    devices over an HTTP- or HTTPS-based API.
version_added: "2.7"
options:
  login_path:
    type: string
    description:
      - Specifies the API token path for logging into the AED device.
    default: '/platform/login'
    vars:
      - name: ansible_httpapi_aed_login_path

  api_path:
    type: string
    description:
      - Specifies the API path for the AED device.
    default: '/api/aed'
    vars:
      - name: ansible_httpapi_aed_api_path

  api_ver:
    type: string
    description:
      - Specifies the API version for the AED device.
    default: '2'
    vars:
      - name: ansible_httpapi_aed_api_ver

  api_token:
    type: string
    description:
      - Specifies the API token for connecting to an AED device, instead of using a username and password.
    vars:
      - name: ansible_httpapi_aed_api_token
"""

AED_DEFAULT_API_PATH_FMT = "/api/aed/v{0}"
"""XXX: I don't think this is used anywhere."""
AED_API_AUTH_COOKIE_NAME = "auth_tkt"
"""XXX: I don't think this is used anywhere."""

HTTP_TEMP_REDIRECT = 302
"""Constant for HTTP code '302 Found'"""

import json

from ansible.module_utils.connection import ConnectionError
from ansible.plugins.httpapi import HttpApiBase
from ansible.module_utils.urls import open_url
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.errors import AnsibleConnectionFailure
from ansible.module_utils.six.moves.urllib.parse import urlencode
from ansible.module_utils._text import to_text


try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display
    display = Display()


class HttpApi(HttpApiBase):
    """httpapi connection plugin sub-plugin for AED devices."""
    def __init__(self, connection):
        """Default constructor

        Args:
            connection (ansible.plugins.connection.httpapi.Connection): Parent
                httpapi connection plugin.
        """
        super(HttpApi, self).__init__(connection)
        self.connection = connection
        """Parent httpapi connection plugin."""
        self.refresh_token = None
        """XXX: I don't think this is used anywhere."""
        self._auth_cookie = None
        """XXX: I don't think this is used anywhere."""
        self._api_spec = None
        """XXX: I don't think this is used anywhere."""

    def login(self, username, password):
        """Callback to login to AED.

        If an API token is specified, that will be used. If not, the specified
        credentials will be used to log into the web UI and scrape the session
        cookie.

        Args:
            username (str): Username to use to log into the web UI
            password (str): Password to use to log into the web UI
        Raises:
            AnsibleConnectionFailure: If the login to the AED fails.
        """
        self.api_token = self.get_option('api_token')

        if self.api_token:
            self.connection._auth = {
                'X-Arbux-APIToken': str(self.api_token)
            }
        else:
            #  Need to get a new cookie-auth
            auth_data = 'username={}&password={}'.format(username, password)

            # Don't use basic auth, instead insert 'auth' header:
            login_url = '{0}{1}'.format(
                self.connection._url,
                self._get_api_login_path()
            )

            try:
                open_url(
                    method="POST",
                    url=login_url,
                    data=auth_data,
                    headers={
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    validate_certs=self.connection._options['validate_certs'],
                    follow_redirects=False,  # Always force for AED
                )
            except HTTPError as exc:
                if exc.code == HTTP_TEMP_REDIRECT:
                    # It's OK - used to hack auth login page
                    # Is there a 'set-cookie'?? Then good!
                    new_cookie = exc.hdrs.dict.get('set-cookie')
                    if new_cookie:
                        self.connection._auth = {'Cookie': str(new_cookie)}
                else:
                    raise AnsibleConnectionFailure(
                        'Could not connect to {0}: {1}'.format(
                            login_url, exc.reason)
                    )
        return

    def send_request(
        self, url_path, http_method, body_params=None,
        path_params=None, query_params=None
    ):
        """Send an authenticated request to the AED.

        Note that this method does not match the method signature of
        HttpApiBase.send_request(), and therefore cannot be used in a
        polymorphic manner.

        XXX: Path params are not currently used anywhere in this module.
        XXX: AEDAPIBase hides the ``success`` key in the dict that is returned,
        so really no one is checking it.

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
        """

        url = self.construct_url_path(url_path, path_params, query_params)
        data = json.dumps(body_params) if body_params else None

        headers = dict()
        if http_method in ("PATCH", "POST", "PUT"):
            headers["Content-type"] = "application/json"

        try:
            response, response_data = self.connection.send(
                path=url,
                data=data,
                method=http_method,
                headers=headers
            )

            return {
                'success': True,
                'status_code': response.getcode(),
                'response': self._response_to_json(response_data.getvalue())
            }

        except HTTPError as e:
            return {
                'success': False,
                'status_code': e.code,
                'response': self._response_to_json(e.read())
            }

    def _get_api_login_path(self):
        """Get the URL path to the AED login page as specified by the
        ``login_path`` option.

        Returns:
            str: The absolute URL path to the AED login page.
        """
        return self.get_option('login_path')

    @staticmethod
    def _response_to_json(response_data):
        """
        Convert JSON body of response to a python object.

        Args:
            response_data (io.BytesIO): Body of HTTP response, as returned by
                ``ansible.plugins.connection.httpapi.Connection.send()``.
        Returns:
            object: Python object representing the response body.
        Raises:
            ConnectionError: if the response body could not be decoded.
        """
        response_text = to_text(response_data)
        try:
            return json.loads(response_text) if response_text else {}
        # JSONDecodeError only available on Python 3.5+
        except getattr(json.decoder, 'JSONDecodeError', ValueError):
            raise ConnectionError('Invalid JSON response: %s' % response_text)

    def handle_httperror(self, exc):
        """Handle HTTP errors raised in
        ``ansible.plugins.connection.httpapi.Connection.send()``.

        Overriding this to return None so we can handle errors at a higher
        layer.

        Returns:
            None: None to force ``send()`` to re-throw the HTTPError exception.
        """
        # TODO Catch unauthorized stuff??
        # None means that the exception will be passed further to the caller
        return None

    def construct_url_path(self, path, path_params=None, query_params=None):
        """Build an absolute URL path.

        Args:
            path (str): Relative URL path. This should be everything that comes
                after the initial ``/api/aed/{version}``.
            path_params (dict): Dict of values to replace in the ``path`` arg
                using ``format()``-style subsititution.
            query_params (dict): Dict of key/value pairs to include in the
                query component of the URL.
        Returns:
            str: Absolute URL path.
        """
        # Connection provides the https://hostname:port, build the rest
        api_path = self.get_option('api_path')
        api_ver = self.get_option('api_ver')
        url = '{0}/v{1}/{2}/'.format(
            api_path,
            api_ver,
            path
        )

        if path_params:
            url = url.format(**path_params)
        if query_params:
            url += "?" + urlencode(query_params)
        return str(url)
