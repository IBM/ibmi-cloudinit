# vi: ts=4 expandtab
#
#    Copyright (C) 2012 Yahoo! Inc.
#
#    Author: Joshua Harlow <harlowja@yahoo-inc.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 3, as
#    published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import functools
import http.client
import json

from cloudinit import log as logging
from cloudinit import url_helper
from cloudinit import util

LOG = logging.getLogger(__name__)
SKIP_USERDATA_CODES = frozenset([http.client.NOT_FOUND])


def maybe_json_object(text):
    if not text:
        return False
    text = text.strip()
    if text.startswith("{") and text.endswith("}"):
        return True
    return False


# See: http://bit.ly/TyoUQs
#
class MetadataMaterializer(object):
    def __init__(self, blob, base_url, caller):
        self._blob = blob
        self._md = None
        self._base_url = base_url
        self._caller = caller

    def _parse(self, blob):
        leaves = {}
        children = []
        if not blob:
            return (leaves, children)

        def has_children(item):
            if item.endswith("/"):
                return True
            else:
                return False

        def get_name(item):
            if item.endswith("/"):
                return item.rstrip("/")
            return item

        for field in blob.splitlines():
            field = field.strip()
            field_name = get_name(field)
            if not field or not field_name:
                continue
            if has_children(field):
                if field_name not in children:
                    children.append(field_name)
            else:
                contents = field.split("=", 1)
                resource = field_name
                if len(contents) > 1:
                    # What a PITA...
                    (ident, sub_contents) = contents
                    ident = util.safe_int(ident)
                    if ident is not None:
                        resource = "%s/openssh-key" % (ident)
                        field_name = sub_contents
                leaves[field_name] = resource
        return (leaves, children)

    def materialize(self):
        if self._md is not None:
            return self._md
        self._md = self._materialize(self._blob, self._base_url)
        return self._md

    def _decode_leaf_blob(self, field, blob):
        if not blob:
            return blob
        if maybe_json_object(blob):
            try:
                # Assume it's json, unless it fails parsing...
                return json.loads(blob)
            except (ValueError, TypeError) as e:
                LOG.warn("Field %s looked like a json object, but it was"
                         " not: %s", field, e)
        if blob.find("\n") != -1:
            return blob.splitlines()
        return blob

    def _materialize(self, blob, base_url):
        (leaves, children) = self._parse(blob)
        child_contents = {}
        for c in children:
            child_url = url_helper.combine_url(base_url, c)
            if not child_url.endswith("/"):
                child_url += "/"
            child_blob = str(self._caller(child_url))
            child_contents[c] = self._materialize(child_blob, child_url)
        leaf_contents = {}
        for (field, resource) in leaves.items():
            leaf_url = url_helper.combine_url(base_url, resource)
            leaf_blob = str(self._caller(leaf_url))
            leaf_contents[field] = self._decode_leaf_blob(field, leaf_blob)
        joined = {}
        joined.update(child_contents)
        for field in leaf_contents.keys():
            if field in joined:
                LOG.warn("Duplicate key found in results from %s", base_url)
            else:
                joined[field] = leaf_contents[field]
        return joined


def _skip_retry_on_codes(status_codes, _request_args, cause):
    """Returns if a request should retry based on a given set of codes that
    case retrying to be stopped/skipped.
    """
    if cause.code in status_codes:
        return False
    return True


def get_instance_userdata(api_version='latest',
                          metadata_address='http://169.254.169.254',
                          ssl_details=None, timeout=5, retries=5):
    ud_url = url_helper.combine_url(metadata_address, api_version)
    ud_url = url_helper.combine_url(ud_url, 'user-data')
    user_data = ''
    try:
        # It is ok for userdata to not exist (thats why we are stopping if
        # NOT_FOUND occurs) and just in that case returning an empty string.
        exception_cb = functools.partial(_skip_retry_on_codes,
                                         SKIP_USERDATA_CODES)
        response = util.read_file_or_url(ud_url,
                                         ssl_details=ssl_details,
                                         timeout=timeout,
                                         retries=retries,
                                         exception_cb=exception_cb)
        user_data = str(response)
    except url_helper.UrlError as e:
        if e.code not in SKIP_USERDATA_CODES:
            util.logexc(LOG, "Failed fetching userdata from url %s", ud_url)
    except Exception:
        util.logexc(LOG, "Failed fetching userdata from url %s", ud_url)
    return user_data


def get_instance_metadata(api_version='latest',
                          metadata_address='http://169.254.169.254',
                          ssl_details=None, timeout=5, retries=5):
    md_url = url_helper.combine_url(metadata_address, api_version)
    md_url = url_helper.combine_url(md_url, 'meta-data')
    caller = functools.partial(util.read_file_or_url,
                               ssl_details=ssl_details, timeout=timeout,
                               retries=retries)

    try:
        response = caller(md_url)
        materializer = MetadataMaterializer(str(response), md_url, caller)
        md = materializer.materialize()
        if not isinstance(md, (dict)):
            md = {}
        return md
    except Exception:
        util.logexc(LOG, "Failed fetching metadata from url %s", md_url)
        return {}
