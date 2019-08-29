#!/usr/bin/env python3
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
from datetime import datetime

import ordinal_sequence_encoder

SCRIPT_DIRECTORY = os.path.dirname(os.path.realpath(__file__))
JSON_INDENT = 4

class ApiError(Exception):
    pass

# This isn't passed anywhere, its values are just used in comparisons.
class ApiMessage(Enum):
    TEMPORARY_BAN = 'You have been temporarily banned, please check the email you have registered to this account for further details.(#3)'
    BAD_ATTRIBUTES = 'Missing Or Invalid Required Attributes. Please check and try again.'
    GUARD_POLICY_CHANGED = 'The Guard policy has been changed.'
    BANK_POLICY_CHANGED = 'The bank policy for all your clan cities has been changed.'
    INVALID_CREDENTIALS = 'Invalid username or password.(#3)'
    INSUFFICIENT_PERMISSION = 'You do not have the sufficient access to perform this operation.'

class RequestOwner(Enum):
    LOGIN = 'EXTBRM'
    CLAN = 'QETUO'
    JOURNAL = 'WRYIP'  # unused
    
# All Referers: the base web url
class LoginWebGateRequest(IntEnum):
    # Query: extra &, WebGateRequest, RequestOwner, _, UserName, RequestOwner (again)
    CHALLENGE_REQUEST = 1
    # Query: extra &, WebGateRequest, _, Password, UserName, RequestOwner
    CHALLENGE_RESPONSE = 2
    # The outer page with the framed navigation panel providing the clan/journal tabs.
    # Query: extra &, SessionKey, WebGateRequest, RequestOwner, RequestOwner (again)
    BROWSER_FRAME = 3  # only used as a referer

# All Referers: the url for LoginWebGateRequest.BROWSER_FRAME
class ClanWebGateRequest(IntEnum):
    # Query: SessionKey, WebGateRequest, RequestOwner
    # Post: ogb=true
    GET_DATA = 1  # I named this; was nothing in the web code to imply a name.
    # Query: SessionKey, WebGateRequest, RequestOwner
    # Post: ClanID=123
    GET_BANNER = 2
    # Query: SessionKey, ClanID, WebGateRequest, RequestOwner
    # Post: id=1
    BANK_POLICY = 9
    # Query: SessionKey, ClanID, WebGateRequest, RequestOwner
    # Post: id=1
    GUARD_POLICY = 36
    # Query: SessionKey, ClanID, WebGateRequest, RequestOwner
    # Post: id=1 (no idea why it sends this)
    CLAN_OVERVIEW_PAGE = 37
    # Query: SessionKey, ClanID, WebGateRequest, RequestOwner
    # Post: NewsReelFilter, TimeFilter, odo=true, GridCurrentStartRow,
    #       GridCurrentPageRows, GridCurrentPage
    NEWS_REEL = 54

# Combines as a sorted colon delimited list of the integer values
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
    
class TimeFilter(IntEnum):
    ONE_DAY = 0
    THREE_DAYS = 1
    SEVEN_DAYS = 2

class BankPolicy(IntEnum):
    ALL = 0
    NON_ENEMY = 1
    ALLIES = 2
    CLAN = 3
    
class GuardPolicy(IntEnum):
    NON_ALLY = 0
    ENEMY = 1
    NOONE = 2

class ClientOption(Enum):
    PRINT_MESSAGE = auto()
    PRINT_REQUEST = auto()
    PRINT_RESPONSE = auto()
    PRINT_APIERROR = auto()
    PRINT_SESSION = auto()
    PRINT_CLAN_ID = auto()
    PRINT_NEWS_REEL = auto()
    MOCKING_ONLY = auto()
    WRITE_MISSING_MOCKS = auto()

class ApiCategory(Enum):
    LOGIN = auto()
    ERROR = auto()
    CLAN = auto()

class ApiHttpConnection(object):
    def __init__(self):
        self.connection = None
        self.host = None
        self.port = None
        self.default_path = None
        self.default_query = None
        
    def connect(self, url):
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.scheme != 'http':
            raise ValueError('Url is not using http scheme.')
        self.default_path = parsed_url.path if parsed_url.path else None
        self.default_query = parsed_url.query if parsed_url.query else None
        self.origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
        parts = parsed_url.netloc.split(':', 1)
        self.host = parts[0]
        self.port = int(parts[1]) if (len(parts) == 2) else 80
        self.reconnect()

    def reconnect(self):
        self.close()
        self.connection = http.client.HTTPConnection(self.host, self.port)
        print("Socket (re)connected.")
        return self.connection
    
    def _get_url(self, path=None, query=None):
        if path is None:
            path = self.default_path
        if query is None:
            query = self.default_query
        encoded_query = None
        if isinstance(query, str):
            encoded_query = query
        elif query is not None:
            encoded_query = urllib.parse.urlencode(query)
        if encoded_query:
            return f"{path}?{encoded_query}"
        return path
    
    def get_request_url(self, path=None, query=None):
        path_query = self._get_url(path=path, query=query)
        return f"{self.origin}{path_query}"
        
    def request(self, path=None, query=None, form_data=None, headers=None, referer=None, print_request=False):
        if self.connection is None:
            raise RuntimeError('No connection.  Did you forget to call connect()?')
        url = self._get_url(path, query)
        if headers is None:
            headers = {}
        headers.update({
            # look like chrome
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
            'Accept': 'application/xml, text/xml, */*',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9',
            'X-Requested-With': 'XMLHttpRequest',
            'Connection': 'keep-alive'
        })
        if referer is not None:
            headers['Referer'] = referer
        if form_data is not None:
            if not isinstance(form_data, str):
                form_data = urllib.parse.urlencode(form_data)
            method = 'POST'
            headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=utf-8'
            headers['Origin'] = self.origin
        else:
            method = 'GET'
        new_connection = False
        while True:
            self.connection.request(method=method, url=url, headers=headers, body=form_data)
            try:
                response_object = self.connection.getresponse()
            except http.client.RemoteDisconnected as e:
                if new_connection:
                    # it happened twice, it isn't just the keep-alive expiring
                    raise  # let is propagate up
                self.reconnect()
                new_connection = True
                continue # run it one more time with the new connection
            break  # it worked!
        # printing the request after the reconnection so the logging order makes more sense
        if print_request:
            print(f"Url: {url}")
            print(f"Post data: {form_data}")
        response = response_object.read()
        return (dict(response_object.headers), response)
        
    def close(self):
        if self.connection:
            self.connection.close()
            self.connection = None

# TODO: consider _requiring_ mock_name
class ApiClient(object):
    """ Connects to the server and manages the session. """
    
    @staticmethod
    def flattened_child_element_text_mapping(element):
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
    def time_string():
        return str(int(time.time()))

    def clear_session(self):
        self.session_key = None
        self.clan_id = None

    def disconnect(self):
        self.clear_session()
        if self.connection:
            self.connection.close()
            self.connection = None
        self.cookie = None
        
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
    
    def default_url(self):
        return self.connection.get_request_url()
        
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
        return self.connection.get_request_url(query=query)
    
    def connect(self):
        self.disconnect()
        # if mocking only, skip connecting... it would be pointless.
        if ClientOption.MOCKING_ONLY not in self.option_set:
            self.connection = ApiHttpConnection()
            self.connection.connect(self.web_url)
        else:
            print('Skipping connection request because MOCKING_ONLY is set.')
        return self.connection

    @staticmethod
    def get_mock_filename(mock_name, mock_category, level=0):
        global SCRIPT_DIRECTORY
        mock_dir = os.path.join(SCRIPT_DIRECTORY, 'mock', mock_category.name.lower())
        mock_path = os.path.join(mock_dir, f"{mock_name.lower()}.mock")
        if level > 0:
            mock_path += '.decoded'
            if level > 1:
                mock_path += f".{level}"
        return mock_path
        
    @staticmethod
    def write_missing_mock_file(mock_name, mock_category, data, level=0):
        mock_path = ApiClient.get_mock_filename(mock_name, mock_category, level)
        if isinstance(data, str):
            data = data.encode('utf-8')
        if not os.path.exists(mock_path):
            mock_dir = os.path.dirname(mock_path)
            if not os.path.exists(mock_dir):
                os.makedirs(mock_dir)
            with open(mock_path, 'wb') as mock_file:
                mock_file.write(data)
            return True
        return False
        
    @staticmethod
    def get_mock_response(mock_name, mock_category, level=0):
        mock_path = ApiClient.get_mock_filename(mock_name, mock_category, level)
        print(f"MockedResponse: {mock_path}")
        # will raise an exception if it doesn't exist
        with open(mock_path, 'rb') as response:
            response_content = response.read().decode('utf-8')
        return response_content
        
    @staticmethod
    def get_message(element):
        message_element = element.find('./ResultNode/Result/Message')
        if message_element is not None:
            return message_element.text
        return None
        
    # NOTE: also honors Set-Cookie for this object, using the cookie that is requested
    def request(self, query=None, form_data=None, headers=None, referer=None, mock_name=None, mock_category=None, expect_xml=None):
        mockable = bool(mock_name and mock_category is not None)
        if mockable and mock_category in self.mock_set:
            response_content = self.__class__.get_mock_response(mock_name, mock_category)
        else:
            if ClientOption.MOCKING_ONLY in self.option_set:
                raise RuntimeError(f"MOCKING_ONLY is set, cannot make actual request: {request_url}")
            # Add any cookie
            if self.cookie:
                if headers is None:
                    headers = {}
                headers['Cookie'] = self.cookie
            response_headers, response_content = self.connection.request(
                    # use the default path
                    query=query,
                    form_data=form_data,
                    headers=headers,
                    referer=referer,
                    print_request=(ClientOption.PRINT_REQUEST in self.option_set)
            )
            # write missing mocks, if necessary
            # needs the bytes type response, so do this before decoding
            if mockable and ClientOption.WRITE_MISSING_MOCKS in self.option_set:
                self.__class__.write_missing_mock_file(mock_name, mock_category, response_content)
            response_content = response_content.decode('utf-8')
            # update the cookie
            new_cookie = response_headers.get('Set-Cookie', None)
            if new_cookie:
                # Example value(no quotes): 'JSESSIONID=abcdefg; Path=/spenefett; HttpOnly'
                self.cookie = new_cookie.split(';', 1)[0]
        if ClientOption.PRINT_RESPONSE in self.option_set:
            print(f"Response: {response_content}")
        # at this point, we have the response, but we need to see if it is xml
        # and if so, pull some things out of it
        level = 1
        while True:
            # this loop only reruns if the 'continue' occurs; otherwise it returns at the end.
            try:
                root_element = ET.fromstring(response_content)
            except:
                root_element = None
            if root_element is not None:
                logout_element = root_element.find('./ObjectData/Logout')
                if logout_element is not None and logout_element.text == 'true':
                    # this is sent whenever the session is invalid
                    raise ApiError('Invalid Session: server sent <Logout>true</Logout>')
                # NOTE: assuming no other kinds of responses will have a 'Data' entry.
                data_element = root_element.find('./Data')
                if data_element is None:
                    # return the xml
                    if expect_xml == False:
                        raise TypeError("Response expected to not be xml, but it is xml.")
                    # Print messages, independent of whether or not they are handled.
                    message = self.__class__.get_message(root_element)
                    if message is not None:
                        if ClientOption.PRINT_MESSAGE in self.option_set:
                            print(f"Api Message: {message}")
                    return root_element
                # encoded page
                response_content = ordinal_sequence_encoder.decode(data_element.text)
                # Write the extra decoded versions for mocks too, for convenience.
                if mockable and ClientOption.WRITE_MISSING_MOCKS in self.option_set:
                    self.__class__.write_missing_mock_file(mock_name, mock_category, response_content, level)
                if ClientOption.PRINT_RESPONSE in self.option_set:
                    print(f"Decoded Response: {response_content}")
                # the decoded message can itself be (and afaik always is) xml, so, a
                # simple way to resolve this is to just repeat the logic
                continue
            if expect_xml == True:
                raise TypeError("Response expected to be xml, but it is not.")
            return response_content
    
    def update_clan_id(self):
        self.clan_id = None  # so if an exception occurs, it is cleared
        # NOTE: if this isn't sent as a post with the Content-Type 'application/x-www-form-urlencoded; charset=utf-8'
        # the response is some page w/ javascript instead of the nice xml output... the code covers this internally
        # but this is worth mentioning.
        root_element = self.request(
            query=[
                ('SessionKey', self.session_key),
                ('WebGateRequest', ClanWebGateRequest.GET_DATA.value),
                ('RequestOwner', RequestOwner.CLAN.value),
            ],
            form_data=[('ogb', 'true')],
            referer=self.browser_frame_url(),
            mock_name="clan",
            mock_category=ApiCategory.LOGIN,
            expect_xml=True
        )
        clan_id_element = root_element.find('./ClanID')
        self.clan_id = clan_id_element.text if (clan_id_element is not None) else None
        if ClientOption.PRINT_CLAN_ID in self.option_set:
            print(f"Clan ID: {self.clan_id}")
        return self.clan_id
        
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
        
    def login(self, user_name, password_sha1):
        # The login pages all have an extra & erroneously added to the query
        # in the embedded javascript code.
        self.clear_session()  # so if an exception occurs, it is cleared
        web_gate_request = LoginWebGateRequest.CHALLENGE_REQUEST
        request_owner = RequestOwner.LOGIN
        retry = True
        # This loop always breaks at the end, but one place continues
        while True:
            # send initial request to get the RCK salt
            root_element = self.request(
                query='&' + urllib.parse.urlencode([
                    ('WebGateRequest', web_gate_request.value),
                    ('RequestOwner', request_owner.value),
                    ('_', self.__class__.time_string()),
                    ('UserName', user_name),
                    ('RequestOwner', request_owner.value)  # Specified again to match client behavior.
                ]),
                referer=self.default_url(),
                mock_name=web_gate_request.name.lower(),
                mock_category=ApiCategory.LOGIN,
                expect_xml=True
            )
            rck_element = root_element.find('./RCK')
            if rck_element is None:
                message = self.__class__.get_message(root_element)
                if message == ApiMessage.BAD_ATTRIBUTES.value:
                    # you get this if you send the challenge request again when it's waiting for the challenge response.
                    if not retry:
                        raise ApiError('Repeated invalid login state.')
                    retry = False
                    print('Invalid login state; retrying...')
                    continue
                elif message == ApiMessage.INVALID_CREDENTIALS.value:
                    # They don't give the RCK if the user doesn't exist, so this
                    # effectively checks if the user exists.
                    raise ApiError('Invalid Credentials: No user with the specified name exists.')
                elif message is not None:
                    raise ApiError(f"Unexpected message: {message}")
                # this state may not actually occur
                raise ApiError('Bad response; missing RCK.')
            else:
                rck = rck_element.text
                salted_password_sha1 = hashlib.sha1((password_sha1.upper() + rck).encode('ascii')).hexdigest().upper()
                web_gate_request = LoginWebGateRequest.CHALLENGE_RESPONSE
                # send the salted password to get the SessionKey
                root_element = self.request(
                    query='&' + urllib.parse.urlencode([
                        ('WebGateRequest', web_gate_request.value),
                        ('_', self.__class__.time_string()),
                        ('Password', salted_password_sha1),
                        ('UserName', user_name),
                        ('RequestOwner', request_owner.value),
                    ]),
                    referer=self.default_url(),
                    mock_name=web_gate_request.name.lower(),
                    mock_category=ApiCategory.LOGIN,
                    expect_xml=True)
                session_key_element = root_element.find('./SessionKey')
                if session_key_element is None:
                    message = self.__class__.get_message(root_element)
                    if message == ApiMessage.INVALID_CREDENTIALS:
                        raise ApiError('Invalid Credentials: Incorrect password.')
                    elif message is not None:
                        raise ApiError(f"Unexpected message: {message.value}")
                    # this state may not actually occur
                    raise ApiError('Bad response; missing SessionKey.')
                session_key = session_key_element.text if (session_key_element is not None) else None
                self.session_key = session_key
                if self.update_clan_id():
                    if ClientOption.PRINT_SESSION in self.option_set:
                        print('New session established.')
                else:
                    self.clear_session()
            break
        return self.session_key
    
    def get_clan_name(self):
        web_gate_request = ClanWebGateRequest.GET_BANNER
        root_element = self.request(
            query=[
                ('SessionKey', self.session_key),
                ('WebGateRequest', web_gate_request.value),
                ('RequestOwner', RequestOwner.CLAN.value)
            ],
            form_data=[('ClanID', self.clan_id)],
            referer=self.browser_frame_url(),
            mock_name=web_gate_request.name.lower(),
            mock_category=ApiCategory.CLAN,
            expect_xml=True
        )
        clan_name_element = root_element.find('./ClanBannerNode/ClanName')
        if clan_name_element is None:
            raise ApiError('Bad response; missing ClanName.')
        return clan_name_element.text

    # When new messages arrive, they arrive on the first page, pushing older entries further back.
    # For this reason, sometimes when requesting a later page, you'll be reading entries that you
    # already read from the end of the prior page.  There's not any great way to work around this
    # and depending upon which message type you're tracking, there's not an obvious answer how to
    # handle deduplicating it... so the duplicates are provided as-is.  The caller must handle that.
    def get_news_reel(self, news_reel_filter, time_filter, oldest_timestamp=None, multipage_delay_seconds=None):
        if isinstance(news_reel_filter, NewsReelFilter):
            news_reel_filter_value = str(news_reel_filter)
        else:
            news_reel_filter_value = ':'.join([str(entry.value) for entry in sorted(news_reel_filter)])
        common_form_data = [
            ('NewsReelFilter', news_reel_filter_value),
            ('TimeFilter', time_filter.value),
            ('odo', 'true')  # Specified to match client behavior; no idea why this is sent.
        ]
        form_data = list(common_form_data)
        page = 1
        result = []
        latest_timedata = None
        while True:
            web_gate_request = ClanWebGateRequest.NEWS_REEL
            suffix = f".{page}" if page > 1 else ''
            root_element = self.request(
                query=[
                    ('SessionKey', self.session_key),
                    ('ClanID', self.clan_id),
                    ('WebGateRequest', web_gate_request.value),
                    ('RequestOwner', RequestOwner.CLAN.value)
                ],
                form_data=form_data,
                mock_name=f"{web_gate_request.name.lower()}{suffix}",
                mock_category=ApiCategory.CLAN,
                expect_xml=True
            )
            if ClientOption.PRINT_NEWS_REEL in self.option_set:
                print(f"Loaded news reel page {page}")
            page += 1
            start_row_element = root_element.find('./ObjectData/GridCurrentStartRow')
            row_per_page_element = root_element.find('./ObjectData/GridRowPerPage')
            current_page_rows_element = root_element.find('./ObjectData/GridCurrentPageRows')
            total_rows_element = root_element.find('./ObjectData/GridTotalRows')
            if None in [start_row_element, row_per_page_element, current_page_rows_element, total_rows_element]:
                raise ApiError("Bad response; missing one or more Grid related fields.")
            start_row = int(start_row_element.text)
            page_row_count = int(current_page_rows_element.text)
            total_rows = int(total_rows_element.text)
            form_data = list(common_form_data)
            form_data.extend([
                ('GridCurrentStartRow', start_row),
                ('GridCurrentPageRows', page_row_count),
                ('GridCurrentPage', page)  # actually the page you want to go to, not 'current'
            ])
            event_elements = root_element.findall('./ObjectData/Events/Event')
            for event_element in event_elements:
                latest_timedata = datetime.strptime(
                    event_element.find('./TimeData').text,
                    '%Y-%m-%d %H:%M:%S'
                )
                text = event_element.find('./Text').text
                result.append((latest_timedata, text))
            if oldest_timestamp is None or latest_timedata < oldest_timestamp or (start_row + page_row_count) > total_rows:
                # Either only getting one page because no timestamp limit specified, the most recent timedata
                # is earlier than the oldest requested so no more pages are needed, or no pages left to request.
                break
            if multipage_delay_seconds is not None:
                # In case you know you're going to be retrieving a lot of pages and don't want spam requests too quickly
                time.sleep(multipage_delay_seconds)
        return result
        
    def get_bank_policy(self):
        web_gate_request = ClanWebGateRequest.BANK_POLICY
        root_element = self.request(
            query=[
                ('SessionKey', self.session_key),
                ('ClanID', self.clan_id),
                ('WebGateRequest', web_gate_request.value),
                ('RequestOwner', RequestOwner.CLAN.value)
            ],
            form_data=[('id', '1')],  # Specified to match client behavior; no idea why this is sent.
            mock_name=web_gate_request.name.lower(),
            mock_category=ApiCategory.CLAN,
            expect_xml=True
        )
        # there is a df123133 (random numbers) intermediary tag, hence the //
        clan_bank_policy_index_element = root_element.find('.//ObjectData/CurrentClanBankPolicy/ClanBankPolicyIndex')
        if clan_bank_policy_index_element is None:
            raise ApiError('Bad response; missing CurrentClanBankPolicy/ClanBankPolicyIndex.')
        return BankPolicy(int(clan_bank_policy_index_element.text))
        
    def set_bank_policy(self, policy):
        web_gate_request = ClanWebGateRequest.BANK_POLICY
        root_element = self.request(
            query=[
                ('SessionKey', self.session_key),
                ('RequestOwner', RequestOwner.CLAN.value),
                ('ClanID', self.clan_id)
            ],
            form_data=[
                ('ClanBankPolicy', policy.value),
                ('OperationType', 1),  # Specified to match client behavior; no idea why this is sent.
                ('WebGateRequest', web_gate_request.value)
            ],
            mock_name=web_gate_request.name.lower(),
            mock_category=ApiCategory.CLAN,
            expect_xml=True
        )
        message = self.__class__.get_message(root_element)
        if message == ApiMessage.INSUFFICIENT_PERMISSION.value:
            result = False
        elif message == ApiMessage.BANK_POLICY_CHANGED.value:
            result = True
        elif message is not None:
            raise ApiError(f"Unexpected message: {message}")
        else:   
            # this state may not actually occur
            raise ApiError('Bad response')
        return result
        
    def get_guard_policy(self):
        web_gate_request = ClanWebGateRequest.GUARD_POLICY
        root_element = self.request(
            query=[
                ('SessionKey', self.session_key),
                ('ClanID', self.clan_id),
                ('WebGateRequest', web_gate_request.value),
                ('RequestOwner', RequestOwner.CLAN.value)
            ],
            form_data=[('id', '1')],  # Specified to match client behavior; no idea why this is sent.
            mock_name=web_gate_request.name.lower(),
            mock_category=ApiCategory.CLAN,
            expect_xml=True
        )
        # there is a df123133 (random numbers) intermediary tag, hence the //
        guard_policy_index_element = root_element.find('.//ObjectData/CurrentGuardPolicy/GuardPolicyIndex')
        if guard_policy_index_element is None:
            raise ApiError('Bad response; missing CurrentGuardPolicy/GuardPolicyIndex.')
        return GuardPolicy(int(guard_policy_index_element.text))
    
    def set_guard_policy(self, policy):
        web_gate_request = ClanWebGateRequest.GUARD_POLICY
        root_element = self.request(
            query=[
                ('SessionKey', self.session_key),
                ('RequestOwner', RequestOwner.CLAN.value),
                ('ClanID', self.clan_id)
            ],
            form_data=[
                ('GuardPolicy', policy.value),
                ('OperationType', 4),  # Specified to match client behavior; no idea why this is sent.
                ('WebGateRequest', web_gate_request.value)
            ],
            mock_name=web_gate_request.name.lower(),
            mock_category=ApiCategory.CLAN,
            expect_xml=True
        )
        message = self.__class__.get_message(root_element)
        if message == ApiMessage.INSUFFICIENT_PERMISSION.value:
            result = False
        elif message == ApiMessage.GUARD_POLICY_CHANGED.value:
            result = True
        elif message is not None:
            raise ApiError(f"Unexpected message: {message}")
        else:   
            # this state may not actually occur
            raise ApiError('Bad response')
        return result
    
    def get_clan_overview(self):
        web_gate_request = ClanWebGateRequest.CLAN_OVERVIEW_PAGE
        root_element = self.request(
            query=[
                ('SessionKey', self.session_key),
                ('ClanID', self.clan_id),
                ('WebGateRequest', web_gate_request.value),
                ('RequestOwner', RequestOwner.CLAN.value)
            ],
            form_data=[('id', '1')],  # Specified to match client behavior; no idea why this is sent.
            mock_name=web_gate_request.name.lower(),
            mock_category=ApiCategory.CLAN,
            expect_xml=True
        )
        # there is a df123133 (random numbers) intermediary tag, hence the //
        overview_element = root_element.find('.//ObjectData/OverviewNode')
        if overview_element is None:
            raise ApiError('Bad response; missing OverviewNode.')
        return self.__class__.flattened_child_element_text_mapping(overview_element)