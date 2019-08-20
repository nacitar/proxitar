import sys
import os
import json
import http.client
import urllib
import urllib.parse
import urllib.request
import time
import hashlib
import xml.etree.ElementTree as ET
from enum import Enum, auto, IntEnum
from collections import deque

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

def api_http_request(url, query=None, form_data=None, headers=None, referer=None, connection=None, print_request=False):
    if query and not isinstance(query, str):
        encoded_query = urllib.parse.urlencode(query)
    else:
        encoded_query = query
    parsed_url, host, port = api_parse_url(url)
    if connection is None:
        persistent = False
        connection = http.client.HttpConnection(host, port)
        url = parsed_url.path
    else:
        persistent = True
    if form_data and not isinstance(form_data, str):
        form_data = urllib.parse.urlencode(form_data)
    if headers is None:
        headers = {}
    headers.update({
        # look like chrome
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
        'Accept': 'application/xml, text/xml, */*',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'en-US,en;q=0.9',
        'X-Requested-With': 'XMLHttpRequest'
    })
    if persistent:
        headers['Connection'] = 'keep-alive'
    if referer is not None:
        headers['Referer'] = referer
        
    if form_data is not None:
        method = 'POST'
        headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=utf-8'
        headers['Origin'] = f"{parsed_url.scheme}://{parsed_url.netloc}"
    else:
        method = 'GET'
    
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
    return (dict(response_object.headers), response)

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

# http://107.155.100.182:50313/spenefett/fwd for frame request
# base url itself gives login page, with javascript with the WebGateRequest/RequestOwner for the challenge request
# - no referer
class RequestOwner(Enum):
    # Request order: challenge request, challenge response, browser frame
    LOGIN = 'EXTBRM'
    
    # Request order: get data, get banner, get menu, clan overview page
    CLAN = 'QETUO'
        
    JOURNAL = 'WRYIP'  # unused
    
class LoginWebGateRequest(IntEnum):
    # Query: extra &, WebGateRequest, RequestOwner, _, UserName, RequestOwner (again)
    # Referer: http://107.155.100.182:50313/spenefett/fwd
    CHALLENGE_REQUEST = 1
    
    # Query: extra &, WebGateRequest, _, Password, UserName, RequestOwner
    # Referer: http://107.155.100.182:50313/spenefett/fwd    
    CHALLENGE_RESPONSE = 2

    # The outer page with the framed navigation panel providing the clan/journal tabs.
    # Has javascript with the RequestOwner and main WebGateRequest for the Clan and Journal tabs
    # Query: extra &, SessionKey, WebGateRequest, RequestOwner, RequestOwner (again)
    # Referer: http://107.155.100.182:50313/spenefett/fwd
    # This URL is the referer for everything other than login requests.
    BROWSER_FRAME = 3  # unused

# All Referers: 
class ClanWebGateRequest(IntEnum):
    # Provides the WebGateRequest for various API functions, banner, menu, overview, clanid
    # Query: SessionKey, WebGateRequest, RequestOwner
    # Post: ogb=true
    GET_DATA = 1  # I named this
    
    # Query: SessionKey, WebGateRequest, RequestOwner
    # Post: ClanID=123
    GET_BANNER = 2 
    
    # Query: SessionKey, WebGateRequest, RequestOwner, ogb=true
    # Post: ClanID=123
    GET_MENU = 3 # unused
    
    # Query: SessionKey, ClanID, WebGateRequest, RequestOwner
    # Post: id=1 (no idea why it sends this)
    CLAN_OVERVIEW_PAGE = 37
    
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
JSON_INDENT = 4

class ApiError(Exception):
    pass

# TODO: consider _requiring_ mock_name, consider writing out missing mocks
# TODO: reorder class methods?
class ApiClient(object):
    """ Connects to the server and manages the session. """
    
    # TODO: rename this method
    @staticmethod
    def element_to_flat_dict(element):
        result = {}
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
        
    def disconnect(self):
        self.clear_session()
        if self.connection:
            self.connection.close()
            self.connection = None
        self.cookie = None
    
    def connect(self):
        self.disconnect()
        parsed_url, host, port = api_parse_url(self.web_url)
        self.connection = ApiHttpConnection()
        self.connection.connect(host, port)
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

    # NOTE: also tracks Set-Cookie for this object
    def request(self, query=None, form_data=None, headers=None, referer=None, mock_name=None, mock_category=None, expect_xml=None):
        global SCRIPT_DIRECTORY
        mocking = mock_name and mock_category is not None and mock_category in self.mock_set
        if mocking:
            mock_path = os.path.join(SCRIPT_DIRECTORY, 'mock', mock_category.name.lower(), f"{mock_name.lower()}.mock")
            with open(mock_path, 'rb') as response:
                response_content = response.read().decode('utf-8')
        else:
            if ClientOption.FORCE_MOCKING in self.option_set:
                raise RuntimeError(f"FORCE_MOCKING is set, cannot make actual request: {request_url}")
            # Add any cookie
            if self.cookie:
                if headers is None:
                    headers = {}
                headers['Cookie'] = self.cookie
                
            response_headers, response_content = self.connection.request(
                    url=self.web_url,
                    query=query,
                    form_data=form_data,
                    headers=headers,
                    referer=referer,
                    print_request=(ClientOption.PRINT_REQUEST in self.option_set)
            )
            response_content = response_content.decode('utf-8')
            # update the cookie
            new_cookie = response_headers.get('Set-Cookie', None)
            if new_cookie:
                # Example value(no quotes): 'JSESSIONID=abcdefg; Path=/spenefett; HttpOnly'
                self.cookie = new_cookie.split(';', 1)[0]
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
    
    def browser_frame_url(self):
        # This is the page that would be loaded at the end of a successful
        # login in the web.  We don't need any of that information though,
        # so we only need the URL for the post-login 'Referer' values.
        # The login pages all have an extra & erroneously added to this by
        # the embedded javascript code.
        query = '&' + urllib.parse.urlencode([
            ('SessionKey', self.session_key),
            ('WebGateRequest', LoginWebGateRequest.BROWSER_FRAME.value),
            ('RequestOwner', RequestOwner.LOGIN.value),
            ('RequestOwner', RequestOwner.LOGIN.value)  # Specified again to match client behavior.
        ])
        return f"{self.web_url}?{query}"
        
    def login(self, user_name, password_sha1):
        self.clear_session()  # so if an exception occurs, it is cleared
        login_web_url = f"{self.web_url}"   
        # The login pages all have an extra & erroneously added to this by
        # the embedded javascript code.
        query = '&' + urllib.parse.urlencode([
            ('WebGateRequest', LoginWebGateRequest.CHALLENGE_REQUEST.value),
            ('RequestOwner', RequestOwner.LOGIN.value),
            ('_', self.__class__.time_string()),
            ('UserName', user_name),
            ('RequestOwner', RequestOwner.LOGIN.value)  # Specified again to match client behavior.
        ])
        # send initial request to get the RCK salt
        root_element = self.request(query=query, referer=self.web_url, mock_name="challenge", mock_category=ApiCategory.LOGIN, expect_xml=True)
        rck_element = root_element.find('./RCK')
        rck = rck_element.text if (rck_element is not None) else None
        if rck:
            salted_password_sha1 = hashlib.sha1((password_sha1.upper() + rck).encode('ascii')).hexdigest().upper()
            query = '&' + urllib.parse.urlencode([
                ('WebGateRequest', LoginWebGateRequest.CHALLENGE_RESPONSE.value),
                ('_', self.__class__.time_string()),
                ('Password', salted_password_sha1),
                ('UserName', user_name),
                ('RequestOwner', RequestOwner.LOGIN.value),
            ])
            # send the salted password to get the SessionKey
            root_element = self.request(query=query, referer=self.web_url, mock_name="success", mock_category=ApiCategory.LOGIN, expect_xml=True)
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
        self.clan_id = None  # so if an exception occurs, it is cleared
        query = [
            ('SessionKey', self.session_key),
            ('WebGateRequest', ClanWebGateRequest.GET_DATA.value),
            ('RequestOwner', RequestOwner.CLAN.value),
        ]
        form_data = [('ogb', 'true')]
        # NOTE: if this isn't sent as a post with the Content-Type 'application/x-www-form-urlencoded; charset=utf-8'
        # the response is some page w/ javascript instead of the nice xml output... the code covers this internally
        # but this is worth mentioning.
        root_element = self.request(query=query, form_data=form_data, referer=self.browser_frame_url(), mock_name="clan", mock_category=ApiCategory.LOGIN, expect_xml=True)
        clan_id_element = root_element.find('./ClanID')
        self.clan_id = clan_id_element.text if (clan_id_element is not None) else None
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
        query = [
            ('SessionKey', self.session_key),
            ('ClanID', self.clan_id),
            ('WebGateRequest', ClanWebGateRequest.CLAN_OVERVIEW_PAGE.value),
            ('RequestOwner', RequestOwner.CLAN.value),
        ]
        # No idea why this value is sent, and the request works without it.
        form_data = [('id', '1')]  # Specified to match client behavior.  
        root_element = self.request(query=query, form_data=form_data, mock_name="overview", mock_category=ApiCategory.CLAN, expect_xml=True)
        # there is a df123133 (random numbers) intermediary tag, hence the //
        overview_element = root_element.find('.//ObjectData/OverviewNode')
        if overview_element is None:
            raise ApiError('Overview response lacked OverviewNode.')
        return self.__class__.element_to_flat_dict(overview_element)
