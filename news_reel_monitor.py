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
# TODO: should clan info lookup use lowercase names?
class NewsReelMonitor(object):
    def __init__(self, client):
        self.client = client
        self.last_check_latest_event_time = None
        self.holdings = {}
        self.player_holding = {}
        self._clan_name = None
        self._current_request_processed_players = set()
        self._name_to_clan_info = {}
    
    def clan_name(self):
        if not self._clan_name:
            self._clan_name = self.client.get_clan_name()
        return self._clan_name
    
    def get_player_clan_info(self, name):
        return self._name_to_clan_info.get(name, (None, None))

    def holding_state(self, holding):
        if holding not in self.holdings:
            self.holdings[holding] = state = HoldingState()
            return state
        return self.holdings[holding]

    def _set_player_info(self, name, clan, rank):
        # only invoked when we know the info is the most recent
        self._name_to_clan_info[name] = (clan, rank)
    
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
                        clan = proximity_match.group('clan')
                        rank = proximity_match.group('rank')
                        present = (proximity_match.group('state') != 'left')

                        if name not in self._current_request_processed_players:
                            # not an older event/state.
                            self._current_request_processed_players.add(name)
                            # update the name to clan info mapping
                            self._set_player_info(name, clan, rank)
                            holding_state = self.holding_state(holding)
                            
                            if holding_state.proximity_event(name, present):
                                previous_holding = self.player_holding.get(name)
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
                                    del self.player_holding[name]
                                player_state = nested_dict(changed_proximity, holding)
                                # { 'Holding' : { 'Player' : (present, is_current) } }
                                player_state[name] = (present, True)
                                self.player_holding[name] = holding
                    else:
                        # resource
                        rank_pattern = f'(?P<rank>{common_ranks}|Supreme General)'  # resources puts a space in "Supreme General"
                        resource_pattern = 'is gathering resources from our (?P<resource>.+)'
                        holding_pattern = 'in (?P<holding>.+)'
                        clan_pattern = 'from the (?P<clan>.+?)'
                        resource_pattern = f'^({rank_pattern} )?{name_pattern}( {clan_pattern})? {resource_pattern} {holding_pattern}\\.$'
                        resource_match = re.match(resource_pattern, event_text)
                        if resource_match:
                            resource = resource_match.group('resource')
                            holding = resource_match.group('holding')
                            name = resource_match.group('name')
                            clan = resource_match.group('clan')
                            rank = resource_match.group('rank')
                            if rank == 'Supreme General':
                                rank = 'SupremeGeneral'  # make it match proximity
                            if rank and not clan:
                                clan = self.clan_name()
                            if name not in self._current_request_processed_players:
                                self._set_player_info(name, clan, rank)
                            holding_state = self.holding_state(holding)
                            if holding_state.resource_event(event_time, name, resource):
                                # { 'Holding' : { 'ResourceName' : { 'Player' : N-hits } } }
                                resource_state = nested_dict(nested_dict(changed_resources, holding), resource)
                                resource_state[name] = resource_state.get(name, 0) + 1
                        else:
                            print(f'UNKNOWN MESSAGE: {event_time} {event_text}')
            self.last_check_latest_event_time = latest_event_time
        finally:
            self._current_request_processed_players.clear()
        return (changed_proximity, changed_resources)