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
# TODO: 'unique' players, output pages, ...
class NewsReelMonitor(object):
    def __init__(self, client):
        self.client = client
        self.last_check_latest_event_time = None
        self.holdings = {}
        self._clan_name = None
        self._current_request_processed_players = set()
        self._name_to_clan_info = {}
    
    def clan_name(self):
        if not self._clan_name:
            self._clan_name = self.client.get_clan_name()
        return self._clan_name
    
    def get_player_clan_info(self, name):
        return self._name_to_clan_info.get(name)

    def _holding_state(self, holding):
        if holding not in self.holdings:
            self.holdings[holding] = state = HoldingState()
            return state
        return self.holdings[holding]

    def _set_player_info(self, name, clan, rank):
        # only invoked when we know the info is the most recent
        self._name_to_clan_info[name] = (clan, rank)
    
    def _process_proximity_event(self, event_time, name, clan, rank, is_enter, holding):
        is_enter_string = 'entered' if is_enter else 'left'
        if name not in self._current_request_processed_players:
            # not an older event/state.
            self._current_request_processed_players.add(name)
            # update the name to clan info mapping
            self._set_player_info(name, clan, rank)
            holding_state = self._holding_state(holding)
            if holding_state.proximity_event(name, is_enter):
                # this is a state change
                #print(f'{event_time} Proximity: [{clan}:{rank}] {name} {is_enter_string} {holding}')
                #print(f'STATE: {holding} {holding_state.players}')
                return True
            return False
        
    def _process_resource_event(self, event_time, name, clan, rank, resource, holding):
        if rank and not clan:
            clan = self.clan_name()
        if name not in self._current_request_processed_players:
            self._set_player_info(name, clan, rank)
        holding_state = self._holding_state(holding)
        if holding_state.resource_event(event_time, name, resource):
            # previously unknown hit
            #print(f'{event_time} Resource: [{clan}:{rank}] {name} hit {holding} {resource}')
            #print(f'STATE: {holding} {list(holding_state.resources[resource].player_hits.keys())}')
            return True
        return False
    
    def _on_unknown_event(self, event_time, event_text):
        print(f'UNKNOWN MESSAGE: {event_time} {event_text}')
        
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
                    clan_pattern = 'from (the Clan of|our clan the) (?P<clan>.+?)'
                    unclanned_name_pattern = '(?P<unclanned_name>[^ ]+ [^ ]+)'
                    state_pattern = '(has )?(?P<state>left|been spotted in|entered)'
                    holding_pattern = 'our city of (?P<holding>.+)'
                    proximity_pattern = f'^({rank_pattern} {name_pattern} {clan_pattern}|{unclanned_name_pattern}) {state_pattern} {holding_pattern}\\.$'
                    proximity_match = re.match(proximity_pattern, event_text)
                    if proximity_match:
                        holding = proximity_match.group('holding')
                        name = proximity_match.group('unclanned_name')
                        if not name:
                            name = proximity_match.group('name')
                        is_enter = (proximity_match.group('state') != 'left')
                        if self._process_proximity_event(
                                event_time,
                                name,
                                proximity_match.group('clan'),
                                proximity_match.group('rank'),
                                is_enter,
                                holding):
                            # { 'Holding' : { 'Player' : state } }
                            player_state = nested_dict(changed_proximity, holding)
                            player_state[name] = is_enter
                    else:
                        # resource
                        rank_pattern = f'(?P<rank>{common_ranks}|Supreme General)'  # resources puts a space in "Supreme General"
                        resource_pattern = 'is gathering resources from our (?P<resource>.+)'
                        holding_pattern = 'in (?P<holding>.+)'
                        clan_pattern = 'from the (?P<clan>.+?)'
                        resource_pattern = f'^({rank_pattern} )?{name_pattern}( {clan_pattern})? {resource_pattern} {holding_pattern}\\.$'
                        resource_match = re.match(resource_pattern, event_text)
                        if resource_match:
                            holding = resource_match.group('holding')
                            name = resource_match.group('name')
                            rank = resource_match.group('rank')
                            if rank == 'Supreme General':
                                rank = 'SupremeGeneral'  # make it match proximity
                            resource = resource_match.group('resource')
                            if self._process_resource_event(
                                    event_time,
                                    name,
                                    resource_match.group('clan'),
                                    rank,
                                    resource,
                                    holding):
                                # { 'Holding' : { 'ResourceName' : { 'Player' : N-hits} } }
                                resource_state = nested_dict(nested_dict(changed_resources, holding), resource)
                                resource_state[name] = resource_state.get(name, 0) + 1
                        else:
                            self._on_unknown_event(event_time, event_text)
            self.last_check_latest_event_time = latest_event_time
        finally:
            self._current_request_processed_players.clear()
        return (changed_proximity, changed_resources)