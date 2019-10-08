#!/usr/bin/env python3
import api_client
import re
MONITORED_CATEGORIES = [api_client.NewsReelFilter.PROXIMITY, api_client.NewsReelFilter.RESOURCES]

# TODO: do we really want to store all the offsets/player_hits... or do we JUST want the last_hit?
# TODO: allow separate connections for resources and proximity?
class ResourceState(object):
    def __init__(self):
        self.player_hits = {}
        self.last_hit = None
    
    def hit_event(self, event_time, name):
        if name in self.player_hits:
            hits = self.player_hits[name]
        else:
            self.player_hits[name] = hits = set()
        if event_time not in hits:
            hits.add(event_time)
            if self.last_hit is None or event_time > self.last_hit:
                self.last_hit = event_time
            return True
        return False
        
class HoldingState(object):
    def __init__(self):
        self.players = set()
        self.resources = {}
    
    def proximity_event(self, name, present):
        was_present = name in self.players
        if was_present:
            self.players.remove(name)
        if present:
            self.players.add(name)
        return (was_present != present)
        
    def resource_event(self, event_time, name, resource):
        if resource in self.resources:
            resource_state = self.resources[resource]
        else:
            self.resources[resource] = resource_state = ResourceState()
        return resource_state.hit_event(event_time, name)
  
def nested_dict(dict_object, key):
    if key in dict_object:
        value = dict_object[key]
    else:
        value = {}
        dict_object[key] = value
    return value

class CasedNameRegistry(object):
    def __init__(self):
        self._names = {}
        self._updated = set()
    def clear_updated(self):
        self._updated.clear()
    def already_updated(self, name):
        return (name.lower() in self._updated)
    def update(self, name):
        lower_name = name.lower()
        if not self.already_updated(lower_name):
            self._names[lower_name] = name
            self._updated.add(lower_name)
        return lower_name
    def get(self, name):
        lower_name = name.lower()
        cased_name = self._names.get(lower_name)
        if cased_name:
            return cased_name
        return name

# TODO: 'unique' players, output pages, ...
# TODO: should clan info lookup use lowercase names?
class NewsReelMonitor(object):
    def __init__(self, client):
        self.client = client
        self.last_check_latest_event_time = None
        self._holdings = {}
        self._player_location = {}
        self._clan_name = None
        self._got_player_proximity_this_update = set()
        self.cased_player_name = CasedNameRegistry()
        self.cased_clan_name = CasedNameRegistry()
        self.cased_holding_name = CasedNameRegistry()
        self.cased_resource_name = CasedNameRegistry()
        self._name_to_clan_info = {}
    
    def clan_name(self):
        if not self._clan_name:
            self._clan_name = self.cased_clan_name.update(self.client.get_clan_name())
        return self._clan_name
    
    def get_player_clan_info(self, name):
        return self._name_to_clan_info.get(name.lower(), (None, None))

    def player_location(self, name):
        return self._player_location.get(name.lower())
        
    def holdings(self):
        return list(self._holdings.keys())
        
    def holding_state(self, holding):
        holding = holding.lower()
        if holding not in self._holdings:
            self._holdings[holding] = state = HoldingState()
            return state
        return self._holdings[holding]
    
    def _common_message_processing(self, match):
        holding = match.group('holding')
        if 'unclanned_name' in match.groups():
            name = match.group('unclanned_name')
        else:
            name = match.group('name')
        clan = match.group('clan')
        rank = match.group('rank')
        if rank == 'Supreme General':
            rank = 'SupremeGeneral'  # make resource feed match proximity
        if rank and not clan:
            clan = self.clan_name()
        
        # store the casing and get the lowercase equivalent
        holding = self.cased_holding_name.update(holding)
        if clan:
            clan = self.cased_clan_name.update(clan)
        # if this is the first time seeing this player this update
        if not self.cased_player_name.already_updated(name):
            name = self.cased_player_name.update(name)
            # update the membership
            self._name_to_clan_info[name] = (clan, rank)
        else:
            # just make it lowercase
            name = name.lower()
        return (holding, name, clan, rank)

    # If a player both enters and leaves a holding between calls, because
    # only the most recent state is reported for a given holding, note that
    # you will get an exit reported even though an entrance was never
    # previously reported.
    def check_for_changes(self):
        global MONITORED_CATEGORIES
        result = self.client.get_news_reel(MONITORED_CATEGORIES, api_client.TimeFilter.ONE_DAY, oldest_event_time = self.last_check_latest_event_time)
        latest_event_time = None
        self._current_request_processed_players = set()
        
        changed_proximity = {}
        changed_resources = {}
        try:
            for page in result:
                for event_time, event_text in page:
                    if self.last_check_latest_event_time is None:
                        self.last_check_latest_event_time = event_time
                    if latest_event_time is None or event_time > latest_event_time:
                        latest_event_time = event_time
                    if event_time < self.last_check_latest_event_time:
                        # Stop early; get_news_reel gives the complete page back to the oldest_event_time
                        # but the extra entries on the page are unneeded.  Due to the behavior of
                        # get_news_reel it's also assuredly the final page, so no need to do a multi-level
                        # break out of these loops.
                        break
                    # common
                    common_ranks='Recruit|Private|Corporal|Sergeant|Lieutenant|Captain|Major|Colonel|General'
                    name_pattern = '(?P<name>[^ ]+ [^ ]+)'
                    # proximity
                    rank_pattern = f'(?P<rank>{common_ranks}|SupremeGeneral)'  # proximity has no space in "SupremeGeneral"
                    clan_pattern = 'from (the Clan of|our clan) the (?P<clan>.+?)'
                    unclanned_name_pattern = '(?P<unclanned_name>[^ ]+ [^ ]+)'
                    state_pattern = '(has )?(?P<state>left|been spotted in|entered)'
                    holding_pattern = 'our city of (?P<holding>.+)'
                    proximity_pattern = f'^({rank_pattern} {name_pattern} {clan_pattern}|{unclanned_name_pattern}) {state_pattern} {holding_pattern}\\.$'
                    proximity_match = re.match(proximity_pattern, event_text)
                    if proximity_match:
                        holding, name, clan, rank = self._common_message_processing(proximity_match)
                        if name not in self._got_player_proximity_this_update:
                            # not an older event/state.
                            self._got_player_proximity_this_update.add(name)
                            holding_state = self.holding_state(holding)
                            present = (proximity_match.group('state') != 'left')
                            if holding_state.proximity_event(name, present):
                                previous_holding = self._player_location.get(name)
                                if previous_holding is not None:
                                    # because I only process the most recent state of any
                                    # particular person within the content of a given update,
                                    # if new messages arrive saying a player left one city and
                                    # also entered another (fast travel will do this) then we
                                    # exit event is basically 'missed', so we'll simulate it
                                    self.holding_state(previous_holding).proximity_event(name, False)
                                    
                                    player_state = nested_dict(changed_proximity, previous_holding)
                                    # { 'Holding' : { 'Player' : (present, is_current) } }
                                    player_state[name] = (False, False)
                                    # even if simply exiting the same holding this updates the state
                                    del self._player_location[name]
                                player_state = nested_dict(changed_proximity, holding)
                                # { 'Holding' : { 'Player' : (present, is_current) } }
                                player_state[name] = (present, True)
                                self._player_location[name] = holding
                    else:
                        # resource
                        rank_pattern = f'(?P<rank>{common_ranks}|Supreme General)'  # resources puts a space in "Supreme General"
                        resource_pattern = 'is gathering resources from our (?P<resource>.+)'
                        holding_pattern = 'in (?P<holding>.+)'
                        clan_pattern = 'from the (?P<clan>.+?)'
                        resource_pattern = f'^({rank_pattern} )?{name_pattern}( {clan_pattern})? {resource_pattern} {holding_pattern}\\.$'
                        resource_match = re.match(resource_pattern, event_text)
                        if resource_match:
                            holding, name, clan, rank = self._common_message_processing(resource_match)
                            holding_state = self.holding_state(holding)
                            resource = resource_match.group('resource')
                            if holding_state.resource_event(event_time, name, resource):
                                resource = self.cased_resource_name.update(resource)
                                # { 'Holding' : { 'ResourceName' : { 'Player' : N-hits } } }
                                resource_state = nested_dict(nested_dict(changed_resources, holding), resource)
                                resource_state[name] = resource_state.get(name, 0) + 1
                        else:
                            print(f'UNKNOWN MESSAGE: {event_time} {event_text}')
            self.last_check_latest_event_time = latest_event_time
        finally:
            self._got_player_proximity_this_update.clear()
            self.cased_player_name.clear_updated()
            self.cased_clan_name.clear_updated()
            # don't clear holding/resource names; they won't be updating
            #self.cased_holding_name.clear_updated()
            #self.cased_resource_name.clear_updated()
        return (changed_proximity, changed_resources)