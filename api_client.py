import sys
import os
import re
import json
import http.client
import urllib
import urllib.parse
import urllib.request
import time
import hashlib
import xml.etree.ElementTree as ET
from enum import Enum, auto, IntEnum
from collections import deque;
# they have an extra & here in their code"/spenefett/fwd?&SessionKey= 

def api_parse_url(url):
    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.query:
        raise ValueError('Query string not allowed in the url.')
    if parsed_url.scheme != 'http':
        raise ValueError('Url is not using http scheme.')
    parts = parsed_url.netloc.split(':', 1)
    if len(parts) == 2:
        port = parts[1]
    else:
        port = 80
    host = parts[0]
    return (parsed_url, host, port)

def api_http_connection(url):
    parsed_url, host, port = api_parse_url(url)
    connection = http.client.HttpConnection(host, port)
    return connection

# Referer: http://107.155.100.182:50313/spenefett/fwd?&SessionKey=KEYHERE&WebGateRequest=3&RequestOwner=EXTBRM&RequestOwner=EXTBRM
def api_http_request(url, query=None, form_data=None, headers=None, referer=None, connection=None, print_request=False):
    if query and not isinstance(query, str):
        encoded_query = urllib.parse.urlencode(query)
    else:
        encoded_query = ''
    if connection is None:
        persistent = False
        parsed_url = api_parse_url(url)[0]
        connection = api_http_connection(url)
        url = parsed_url.path
    else:
        persistent = True
    if form_data and not isinstance(form_data, str):
        # allow for some flexibility here
        form_data = urllib.parse.urlencode(form_data)
    if headers is None:
        headers = {}
    headers.update({
        # look like chrome
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
        'Accept-Language': 'en-US,en;q=0.9'
        #'Cache-Control:': 'max-age=0'  # only on main page load so far
    })
    if persistent:
        headers['Connection'] = 'keep-alive'
    if referer is not None:
        headers['Referer'] = referer
    method = 'POST' if (form_data is not None) else 'GET'
    if encoded_query:
        request_url = f"{url}?{encoded_query}"
    else:
        request_url = url
    if print_request:
        print(f"Request: {request_url}")
        print(f"Post data: {form_data}")
    connection.request(method=method, url=request_url, headers=headers, body=form_data)
    response_object = connection.getresponse()
    response = response_object.read()
    if not persistent:
        connection.close()
    return response

class ApiHttpConnection(object):
    def __init__(self):
        self.connection = None
        
    def connect(self, host, port):
        if self.connection:
            self.close()
        self.connection = http.client.HTTPConnection(host, port)
        return self.connection
    
    def request(self, url, query=None, form_data=None, headers=None, referer=None, print_request=False):
        if self.connection is None:
            raise RuntimeError('No connection.  Did you forget to call connect()?')
        return api_http_request(url=url, query=query, form_data=form_data, headers=headers, referer=referer, connection=self.connection, print_request=print_request)
        
    def close(self):
        if self.connection:
            self.connection.close()
            self.connection = None

# after logging out, has old session key http://107.155.100.182:50313/spenefett/fwd?SessionKey=OLDKEYHERE
# http://107.155.100.182:50313/spenefett/fwd for frame request
# base url itself gives login page, with javascript with the WebGateRequest/RequestOwner for the challenge request
class RequestOwner(Enum):
    LOGIN = 'EXTBRM'
    CLAN = 'QETUO'
    JOURNAL = 'WRYIP'
    
class LoginWebGateRequest(IntEnum):
    CHALLENGE_REQUEST = 1
    CHALLENGE_RESPONSE = 2
    # The outer page with the framed navigation panel providing
    # the clan/journal tabs.
    # In javascript has RequestOwner and main WebGateRequest for Clan and Journal tabs
    BROWSER_FRAME = 3
        # Query: SessionKey, WebGateRequest, RequestOwner, RequestOwner (again)
        # referer: http://107.155.100.182:50313/spenefett/fwd
        # This serves as every referer after

class ClanWebGateRequest(IntEnum):
    # Provides the WebGateRequest for various API functions, banner, menu, overview, clanid
    GET_NAVIGATION_INFORMATION = 1
    GET_BANNER = 2
    GET_MENU = 3
    CLAN_OVERVIEW_PAGE = 37
    
class JournalWebGateRequest(IntEnum):
    GET_NAVIGATION_INFORMATION = 1  # nothing useful is here, it just gives the WebGateRequest for the MENU
    MENU = 2
    
class NewsReelFilter(IntEnum):
    BINDS = 0
    PROXIMITY = 1
    CONNECTIONS = 2
    POLITICS = 3
    RANKS = 4
    STRUCTURES = 5
    RESOURCES = 6
    WORKSTATIONS = 7
    MEMBERS = 8
    CONTROL_POINTS = 9
    FORTRESSES = 10
    MISC = 11
# assembles as colon delimited sorted numbers
    
class TimeFilter(IntEnum):
    ONE_DAY = 0,
    THREE_DAYS = 1,
    SEVEN_DAYS = 2

class ClientOption(Enum):
    PRINT_REQUEST = auto()
    PRINT_RESPONSE = auto()
    PRINT_APIERROR = auto()
    PRINT_SESSION = auto()
    PRINT_CLANID = auto()
    FORCE_MOCKING = auto()

class ApiCategory(Enum):
    LOGIN = auto()
    ERROR = auto()
    CLAN = auto()

SCRIPT_DIRECTORY = os.path.dirname(os.path.realpath(__file__))
CLANID_REGEX = re.compile(r"^\s*var\s+ClanID\s+=\s+'(\d+)'\s*$", re.MULTILINE)
JSON_INDENT = 4

class ApiError(Exception):
    pass

# TODO: consider _requiring_ mock_name, consider writing out missing mocks
# TODO: reorder class methods?
class ApiClient(object):
    """ Connects to the server and manages the session. """
    
    @staticmethod
    def element_to_flat_dict(element):
        result = {}
        # the queue is modified during iteration, so, we must use indexes instead of a foreach
        queue = deque([(None, list(element))])
        while len(queue):
            prefix, children = queue.popleft()
            for child_element in children:
                if prefix:
                    key = f"{prefix}.{child_element.tag}"
                else:
                    key = child_element.tag
                nested_children = list(child_element)
                if nested_children:
                    queue.append((key, nested_children))
                else:
                    result[key] = child_element.text
        return result
    @staticmethod
    def decode(data):
        output = ''
        offset_map = {}
        entries = data.split(',')
        for i in range(len(entries)):
            # Store the index into the output buffer so references can get
            # start of this entry and can deduce that it ends at either the
            # start of the next entry or the end of the full output if this
            # entry is the last.
            offset_map[i] = len(output)
            entry = entries[i].strip()
            if entry.startswith('_'):
                # An entry prefixed with an underscore (a reference) is the
                # ASCII representation of the zero-based integer index of a
                # prior entry in the input data, indicating that the output of
                # this entry is the output of the referenced entry
                # concatenated with the first character of the output of the
                # entry after the referenced entry.
                #
                # For example, _0 indicates that the output of this entry is
                # the output of the first entry (index 0) in the input data
                # concatenated with the first character of the output of the
                # second entry (index 1) in the input data.
                reference_index = int(entry[1:])
                if reference_index >= i:
                    # Can't reference this entry or any future entry.
                    raise ValueError(
                        f"Invalid back reference in entry {i}, references"
                        f" future entry {reference_index}: {data}"
                    )
                offset = offset_map[reference_index]
                next_offset = offset_map[reference_index+1]
                if reference_index == (i-1):
                    # If the reference is to the previous entry, then the
                    # first character of the output of this entry will also be
                    # the last character of the output of this entry.  The
                    # output buffer of course does not yet have any of the
                    # output of this entry written.  The logic thus follows to
                    # write the first character of the output of this entry
                    # first, and then write the rest which will end with that
                    # newly written character.
                    output += output[offset]
                    output += output[offset+1:next_offset+1]
                else:
                    # For every index earlier than the prior one, both the
                    # referenced entry and the entry after it are both already
                    # written to the output buffer, thus the output of this
                    # entry can be copied over in one operation.
                    output += output[offset:next_offset+1]
            else:
                # An entry not prefixed by an underscore is the decimal ASCII
                # representation of a character, indicating that the output of
                # this entry is that character.
                output += chr(int(entry))
        return output

    @staticmethod
    def time_string():
        return str(int(time.time()))

    def clear_session(self):
        self.session_key = None
        self.clan_id = None
        
    def __init__(self, web_url, session_file=None, mock_set=None, option_set=None):
        self.web_url = web_url
        self.mock_set = set(mock_set) if (mock_set is not None) else set()
        # it never makes sense for ERROR to not be mocked... you'd always be expecting
        # success, thus an error is only useful here in testing/mocking.
        self.mock_set.add(ApiCategory.ERROR)
        self.option_set = set(option_set) if (option_set is not None) else {
            ClientOption.PRINT_APIERROR
        }
        self.session_file = session_file
        self.connection = None
        self.disconnect()
        
    
    # TODO: migrate to connection object
    def disconnect(self):
        self.clear_session()
        if self.connection:
            self.connection.close()
            self.connection = None
    
    def connect(self):
        self.disconnect()
        parsed_url, host, port = api_parse_url(self.web_url)
        self.connection = ApiHttpConnection()
        self.connection.connect(host, port)
        self.request_root = parsed_url.path
        return self.connection

    def load_session(self):
        try:
            with open(self.session_file) as handle:
                session = json.loads(handle.read()).get('Session',{})
        except FileNotFoundError:
            session = {}
        new_session_key = session.get('SessionKey', None)
        new_clan_id = session.get('ClanID', None)
        if new_session_key and new_clan_id:
            if self.use_session(new_session_key, new_clan_id):
                if ClientOption.PRINT_SESSION in self.option_set:
                    print(f"Session was loaded from file: {self.session_file}")
        if not self.session_key:
            if ClientOption.PRINT_SESSION in self.option_set:
                print(f"Session in file is not valid: {self.session_file}")
        return self.session_key

    def request(self, query=None, form_data=None, mock_name=None, mock_category=None, expect_xml=None):
        global SCRIPT_DIRECTORY
        # TODO: headers, referer
        mocking = mock_name and mock_category is not None and mock_category in self.mock_set
        if mocking:
            mock_path = os.path.join(SCRIPT_DIRECTORY, 'mock', mock_category.name.lower(), f"{mock_name.lower()}.mock")
            with open(mock_path, 'rb') as response:
                response_content = response.read().decode('utf-8')
        else:
            if ClientOption.FORCE_MOCKING in self.option_set:
                raise RuntimeError(f"FORCE_MOCKING is set, cannot make actual request: {request_url}")
            response_content = self.connection.request(
                    url=self.request_root,
                    query=query,
                    form_data=form_data,
                    print_request=(ClientOption.PRINT_REQUEST in self.option_set)
            ).decode('utf-8')
        if mocking:
            print(f"MockedResponse: {mock_path}")
        if ClientOption.PRINT_RESPONSE in self.option_set:
            print(f"Response: {response_content}")
        # at this point, we have the response, but we need to see if it is xml
        # and if so, pull some things out of it
        while True:
            # this loop only reruns if the 'continue' occurs; otherwise it returns at the end.
            try:
                root_element = ET.fromstring(response_content)
            except:
                root_element = None
            if root_element is not None:
                error_element = root_element.find('./ResultNode/Result/Message')
                if error_element is not None:
                    # TODO: remove print?
                    if ClientOption.PRINT_APIERROR in self.option_set:
                        print(f"Server Error Message: {error_element.text}")
                    # this failure can propagate out to the wrapper and it can reconnect
                    raise ApiError(error_element.text)
                logout_element = root_element.find('./ObjectData/Logout')
                if logout_element is not None and logout_element.text == 'true':
                    # this is sent whenever the session is invalid
                    raise ApiError('Invalid Session: server sent <Logout>true</Logout>')
                # TODO: can we really assume no other xml will have a 'Data' entry?
                data_element = root_element.find('./Data')
                if data_element is None:
                    # return the xml
                    if expect_xml == False:
                        raise TypeError("Response expected to not be xml, but it is xml.")
                    return root_element
                # encoded page
                response_content = self.__class__.decode(data_element.text)
                if ClientOption.PRINT_RESPONSE in self.option_set:
                    print(f"Decoded Response: {response_content}")
                # the decoded message can itself be (and afaik always is) xml, so, a
                # simple way to resolve this is to just repeat the logic
                continue
            if expect_xml == True:
                raise TypeError("Response expected to be xml, but it is not.")
            return response_content

    def save_session(self):
        global JSON_INDENT
        if self.session_file:
            json_string = json.dumps(
                {
                    'Session':{
                        'SessionKey': self.session_key,
                        'ClanID': self.clan_id
                    }
                },
                indent=JSON_INDENT, sort_keys=True
            )
            try:
                with open(self.session_file, 'w') as handle:
                    handle.write(json_string)
                if ClientOption.PRINT_SESSION in self.option_set:
                    print(f"Session was saved to file: {self.session_file}")
                return True
            except Exception as e:
                print(e)
                # this message shouldn't be able to be turned off
                print(f"Exception when writing session file: {self.session_file}")
        return False
    
    def validate_session(self):
        old_clan_id = self.clan_id
        if old_clan_id is not None:
            try:
                self.update_clan_id()
            except ApiError as e:
                print(e)
        if self.clan_id is None or self.clan_id != old_clan_id:
            if ClientOption.PRINT_SESSION in self.option_set:
                print('Session validation failed; clearing session.')
            self.clear_session()
        if self.clan_id:
            if ClientOption.PRINT_SESSION in self.option_set:
                print('Session validation successful.')
        return self.session_key
    
    def use_session(self, session_key, clan_id):
        if session_key and clan_id:
            self.session_key = session_key
            self.clan_id = clan_id
            self.validate_session()
        else:
            self.clear_session()
        return self.session_key
    
    def login(self, user_name, password_sha1):
        self.clear_session()  # so if an exception occurs, it is cleared
        parameters = {
            'WebGateRequest': '1',
            'RequestOwner': 'EXTBRM',
            '_': self.__class__.time_string(),
            'UserName': user_name,
        }
        # send initial request to get the RCK salt
        root_element = self.request(parameters, "challenge", ApiCategory.LOGIN, expect_xml=True)
        rck_element = root_element.find('./RCK')
        rck = rck_element.text if (rck_element is not None) else None
        if rck:
            salted_password_sha1 = hashlib.sha1((password_sha1.upper() + rck).encode('ascii')).hexdigest().upper()
            parameters.update({
                'WebGateRequest': '2',
                '_': self.__class__.time_string(),
                'Password': salted_password_sha1
            })
            # send the salted password to get the SessionKey
            root_element = self.request(parameters, "success", ApiCategory.LOGIN, expect_xml=True)
            session_key_element = root_element.find('./SessionKey')
            session_key = session_key_element.text if (session_key_element is not None) else None
            
            self.session_key = session_key
            if self.update_clan_id():
                if ClientOption.PRINT_SESSION in self.option_set:
                    print('New session established.')
            else:
                self.clear_session()
        return self.session_key

    def update_clan_id(self):
        global CLANID_REGEX
        self.clan_id = None  # so if an exception occurs, it is cleared
        parameters = {
            'WebGateRequest': '1',
            'RequestOwner': 'QETUO',
            'SessionKey': self.session_key
        }
        response = self.request(parameters, "clan", ApiCategory.LOGIN, expect_xml=False)
        match = CLANID_REGEX.search(response)
        self.clan_id = CLANID_REGEX.search(response).group(1) if match else None
        if ClientOption.PRINT_CLANID in self.option_set:
            print(f"ClanID: {self.clan_id}")
        return self.clan_id
    
    def get_clan_overview(self):
        parameters = {
            'ClanID': self.clan_id,
            'WebGateRequest': '37',
            'RequestOwner': 'QETUO',
            'SessionKey': self.session_key
        }
        root_element = self.request(parameters, "overview", ApiCategory.CLAN, expect_xml=True)
        # there is a df123133 (random numbers) intermediary tag, hence the //
        overview_element = root_element.find('.//ObjectData/OverviewNode')
        if overview_element is None:
            raise ApiError('Overview response lacked OverviewNode.')
        return self.__class__.element_to_flat_dict(overview_element)
