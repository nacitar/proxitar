#!/usr/bin/env python3
import api_client
import re
MONITORED_CATEGORIES = [api_client.NewsReelFilter.PROXIMITY, api_client.NewsReelFilter.RESOURCES]
     
class HoldingState(object):
    def __init__(self):
        self.players = {}
    
    def proximity_event(self, name, present, clan, rank):
        if name in self.players:
            del self.players[name]
        if present:
            self.players[name] = (clan, rank)

# TODO: keep up with name ==> clan, rank mapping separately from proximity
class NewsReelMonitor(object):
    def __init__(self, client):
        self.client = client
        self.last_check_latest_event_time = None
        self._clan_name = None
        self._current_request_processed_players = set()
        self._holding_state = {}
    
    def clan_name(self):
        if not self._clan_name:
            self._clan_name = self.client.get_clan_name()
        return self._clan_name
    
    def holding_state(self, holding):
        if holding not in self._holding_state:
            self._holding_state[holding] = HoldingState()
        return self._holding_state[holding]

    def _on_proximity_event(self, event_time, name, rank, clan, is_enter, holding):
        is_enter_string = 'entered' if is_enter else 'left'
        if name not in self._current_request_processed_players:
            # not an older event/state.
            self._current_request_processed_players.add(name)
            
            holding_state = self.holding_state(holding)
            holding_state.proximity_event(name, is_enter, clan, rank)
            
            # TODO: determine if the state is NEW (using return of holding_state.proximity_event?)
            # TODO: 'unique' counts
            print(f'{event_time} Proximity: [{clan}:{rank}] {name} {is_enter_string} {holding}')
            print(f'STATE: {holding} {holding_state.players}')
        
    def _on_resource_event(self, event_time, name, rank, clan, resource, holding):
        if rank and not clan:
            clan = self.clan_name()
        # TODO: figure out what should be done here
        print(f'{event_time} Resource: [{clan}:{rank}] {name} hit {holding} {resource}')
    
    def _on_unknown_event(self, event_time, event_text):
        print(f'UNKNOWN MESSAGE: {event_time} {event_text}')
        
    def check(self):
        global MONITORED_CATEGORIES
        result = self.client.get_news_reel(MONITORED_CATEGORIES, api_client.TimeFilter.ONE_DAY, oldest_event_time = self.last_check_latest_event_time)
        latest_event_time = None
        self._current_request_processed_players = set()
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
                    rank_pattern = '(?P<rank>Recruit|Private|Corporal|Sergeant|Lieutenant|Captain|Major|Colonel|(Supreme)?General)'
                    name_pattern = '(?P<name>[^ ]+ [^ ]+)'
                    # proximity
                    clan_pattern = 'from (the Clan of|our clan the) (?P<clan>.+?)'
                    unclanned_name_pattern = '(?P<unclanned_name>[^ ]+ [^ ]+)'
                    state_pattern = '(has )?(?P<state>left|been spotted in|entered)'
                    holding_pattern = 'our city of (?P<holding>.+)'
                    proximity_pattern = f'^({rank_pattern} {name_pattern} {clan_pattern}|{unclanned_name_pattern}) {state_pattern} {holding_pattern}\\.$'
                    proximity_match = re.match(proximity_pattern, event_text)
                    if proximity_match:
                        name = proximity_match.group('unclanned_name')
                        if not name:
                            name = proximity_match.group('name')
                        self._on_proximity_event(
                                event_time,
                                name,
                                proximity_match.group('rank'),
                                proximity_match.group('clan'),
                                (proximity_match.group('state') != 'left'),
                                proximity_match.group('holding'))
                    else:
                        # resource
                        resource_pattern = 'is gathering resources from our (?P<resource>.+)'
                        holding_pattern = 'in (?P<holding>.+)'
                        clan_pattern = 'from the (?P<clan>.+?)'
                        resource_pattern = f'^({rank_pattern} )?{name_pattern}( {clan_pattern})? {resource_pattern} {holding_pattern}\\.$'
                        resource_match = re.match(resource_pattern, event_text)
                        if resource_match:
                            self._on_resource_event(
                                    event_time,
                                    resource_match.group('name'),
                                    resource_match.group('rank'),
                                    resource_match.group('clan'),
                                    resource_match.group('resource'),
                                    resource_match.group('holding')
                            )
                        else:
                            self._on_unknown_event(event_time, event_text)
            self.last_check_latest_event_time = latest_event_time
        finally:
            self._current_request_processed_players.clear()