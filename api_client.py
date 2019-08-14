import sys
import os
import re
import json
import urllib
import urllib.parse
import urllib.request
import time
import hashlib
import xml.etree.ElementTree as ET
from enum import Enum, auto
from collections import deque

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
            # store the index into the output buffer for the start of this entry
            offset_map[i] = len(output)
            entry = entries[i].strip()
            if entry.startswith('_'):
                # entries that start with _ are back references that indicate that the entire contents
                # of the value produced by the entry of the corresponding index... and the first character
                # of the value produced by the NEXT entry.  For example, _0 means to get the value
                # produced by the first entry (index 0) in this list, and the first character of the value
                # produced by the second entry (index 1) in this list.
                back_ref = int(entry[1:])
                if back_ref >= i:
                    # can't really do much better than raising the exception.. whatever data I might
                    # provide would definitely be wrong, but this way it won't be silent about it.
                    raise ValueError(f"Invalid back reference in entry {i}, references future entry {back_ref}: {data}")
                offset = offset_map[back_ref]
                next_offset = offset_map[back_ref+1]
                # if there were never any backreferences to the entry immediately prior to the current one
                # this could be written: output += output[offset:next_offset+1]
                # However, we cannot because the first character of the next entry would then be the first
                # character of THIS entry, which isn't in the buffer yet... so we have to add that character first, just in case.
                output += output[offset]
                output += output[offset+1:next_offset+1]
            else:
                # entries without a _ prefix are just ascii values for a single character.
                output += chr(int(entry))
        return output

    @staticmethod
    def time_string():
        return str(int(time.time()))

    def __init__(self, web_url):
        self.web_url = web_url
        self.mock_set = set()  # {} is a dict, so, use set()
        self.option_set = {
                ClientOption.PRINT_APIERROR,
                ClientOption.PRINT_CLANID,
                ClientOption.PRINT_SESSION}
        self.session_key = None # string
        self.clan_id = None # int
        self.session_file = None
    
    def use_session_file(self, session_file):
        self.session_file = session_file
        try:
            with open(session_file) as handle:
                session = json.loads(handle.read()).get('Session',{})
        except FileNotFoundError:
            session = {}
        new_session_key = session.get('SessionKey', None)
        new_clan_id = session.get('ClanID', None)
        if new_session_key and new_clan_id:
            new_clan_id = int(new_clan_id)
            # don't save, because we just loaded it
            if self.use_session(new_session_key, new_clan_id, save=False):
                if ClientOption.PRINT_SESSION in self.option_set:
                    print(f"Session was loaded from file: {self.session_file}")
        if not self.session_key:
            if ClientOption.PRINT_SESSION in self.option_set:
                    print(f"Session in file is not valid: {self.session_file}")
        return self.session_key

    def request(self, parameters, mock_name=None, mock_category=None, expect_xml=None):
        global SCRIPT_DIRECTORY
        # parameters dictionary ==> query string
        encoded_parameters = urllib.parse.urlencode(parameters)
        request_url = f"{self.web_url}?{encoded_parameters}"
        if ClientOption.PRINT_REQUEST in self.option_set:
            print(f"Request: {request_url}")
        mocking = mock_name and mock_category is not None and mock_category in self.mock_set
        if mocking:
            mock_path = os.path.join(SCRIPT_DIRECTORY, 'mock', mock_category.name.lower(), f"{mock_name.lower()}.mock")
            with open(mock_path, 'rb') as response:
                response_content = response.read().decode('utf-8')
        else:
            if ClientOption.FORCE_MOCKING in self.option_set:
                raise RuntimeError(f"FORCE_MOCKING is set, cannot make actual request: {request_url}")
            with urllib.request.urlopen(request_url) as response:
                response_content = response.read().decode('utf-8')
        if mocking:
            print(f"MockedResponse: {mock_path}")
        if ClientOption.PRINT_RESPONSE in self.option_set:
            print(f"Response: {response_content}")
        # at this point, we have the response, but we need to see if it is xml
        # and if so, pull some things out of it
        while True:
            # this loop only reruns if the 'continue' occurs; otherwise it returns a the end.
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
        if self.session_file and self.session_key:
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
            except Exception as e:
                print(e)
                # this message shouldn't be able to be turned off
                print(f"Exception when writing session file: {self.session_file}")

    # clan_id is used for optional validation
    def use_session(self, session_key, clan_id=None, save=True):
        global JSON_INDENT
        self.session_key = session_key
        success = False
        try:
            self.get_clan_id()
        except ApiError as e:
            print(e)
         
        if self.clan_id:
            if clan_id is not None and int(clan_id) != self.clan_id:  # int cast is just in case someone passes in a string clan_id
                if ClientOption.PRINT_SESSION in self.option_set:
                    print("The retrieved clan id does not match the one specified, so this session key could belong to someone else by some strange coincidence.  A new session will need to be created.")
            else:
                success = True
        if success:
            if ClientOption.PRINT_SESSION in self.option_set:
                print(f"Session ready.")
            if save:
                self.save_session()
        else:
            self.clan_id = None
            self.session_key = None
        return self.session_key

    def login(self, user_name, password_sha1):
        self.session_key = None  # so if an exception occurs, it is cleared
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
            self.use_session(session_key)
        return self.session_key

    def get_clan_id(self):
        global CLANID_REGEX
        self.clan_id = None  # so if an exception occurs, it is cleared
        parameters = {
            'WebGateRequest': '1',
            'RequestOwner': 'QETUO',
            'SessionKey': self.session_key
        }
        response = self.request(parameters, "clan", ApiCategory.LOGIN, expect_xml=False)
        match = CLANID_REGEX.search(response)
        self.clan_id = int(CLANID_REGEX.search(response).group(1) if match else None)
        if ClientOption.PRINT_CLANID in self.option_set:
            print(f"ClanID: {self.clan_id}")
        return self.clan_id
    
    def overview(self):
        parameters = {
            'ClanID': self.clan_id,
            'WebGateRequest': 37,
            'RequestOwner': 'QETUO',
            'SessionKey': self.session_key
        }
        root_element = self.request(parameters, "overview", ApiCategory.CLAN, expect_xml=True)
        # there is a df123133 (random numbers) intermediary tag, hence the //
        overview_element = root_element.find('.//ObjectData/OverviewNode')
        if overview_element is not None:
            return self.__class__.element_to_flat_dict(overview_element)
        raise ApiError('Overview response lacked OverviewNode.')
