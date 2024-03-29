#!/usr/bin/env python3

# TODO: how will commands handle incorrectly cased names?  will need to be able to do that, preferably without losing original case in messages.
# TODO: initial 'all clear'? here, or in main?
# TODO: save 'seen' persistently upon changes?

# TODO: commands, reporting/unique players (later), saving 'seen' to disk
# figure out clearing of state after a disconnect (or is that a 'main' thing?)

# TODO: inverted warnings, for population info
import news_reel_monitor
import bisect
import datetime
from enum import Enum, auto
 
UNCLANNED_PLACEHOLDER = 'unclanned'
 
class DataSetCategory(Enum):
    ADMINISTRATOR = 'admin'
    ALLY_CLAN = 'allyclan'
    ALLY_PLAYER = 'allyplayer'
    IGNORE_CLAN = 'ignoreclan'
    IGNORE_PLAYER = 'ignoreplayer'
    IGNORE_HOLDING = 'ignoreholding'
    
class DataMappingCategory(Enum):
    FILTER_PLAYER = 'filterplayer'
    FILTER_CLAN = 'filterclan'
    FILTER_HOLDING = 'filterholding'
    
def oxford_comma_delimited_string(entries):
    count = len(entries)
    if count:
        if count == 1:
            return entries[0]
        return f"{', '.join(entries[:-1])}, and {entries[-1]}"
    return ''

class AlertBot(object): 
    def __init__(self, monitor):
        self.holding_alert = {}
        self.monitor = monitor
        self.seen_players = {}
        # TODO: the 'unique' stuff
        self._data_sets = {}
        self._data_mappings = {}
    
    def data_set(self, category):
        data = self._data_sets.get(category)
        if data is None:
            self._data_sets[category] = data = set()
        return data
    
    def data_mapping(self, category):
        data = self._data_mappings.get(category)
        if data is None:
            self._data_mappings[category] = data = {}
        return data
        
    def is_friendly(self, name, clan):
        name = name.lower()
        clan = clan.lower()
        return (
                name in self.data_set(DataSetCategory.ALLY_PLAYER) or
                clan in self.data_set(DataSetCategory.ALLY_CLAN) or
                name in self.data_set(DataSetCategory.IGNORE_PLAYER) or
                clan in self.data_set(DataSetCategory.IGNORE_CLAN)
        )
        
    def filter_player(self, name):
        # TODO: offensive/stupid player names
        filtered_name = self.data_mapping(DataMappingCategory.FILTER_PLAYER).get(name.lower())
        if filtered_name is not None:
            return filtered_name
        return name
        
    def filter_clan(self, clan):
        if clan is None:
            global UNCLANNED_PLACEHOLDER
            return UNCLANNED_PLACEHOLDER
        # TODO: offensive/stupid clan names
        filtered_clan = self.data_mapping(DataMappingCategory.FILTER_CLAN).get(clan.lower())
        if filtered_clan is not None:
            return filtered_clan
        return clan
        
    def filter_holding(self, holding):
        # TODO: change it to change how TTS pronounces it?  to fix the capitalization of certain cities?
        filtered_holding = self.data_mapping(DataMappingCategory.FILTER_HOLDING).get(holding.lower())
        if filtered_holding is not None:
            return filtered_holding
        return holding
        
    def _get_alerts(self, full_status, all_warnings_on_change=False):
        any_alert_changed = False
        prioritized_warnings = []
        notices = []
        total_enemies = 0
        if full_status:
            all_warnings_on_change = True
        # for simplicity, just always check all holdings... we only report new events anyway,
        # and this is necessary for 'all clear' messages anyway
        for holding in self.monitor.holdings():
            holding_string = self.filter_holding(holding)
            if holding_string == holding:
                # unfiltered, fix the case instead
                holding_string = self.monitor.cased_holding_name.get(holding)
            # Get the full holding message
            last_alert = self.holding_alert.get(holding)
            if last_alert is None:
                self.holding_alert[holding] = last_alert = f'{holding_string} is clear'
            holding_state = self.monitor.holding_state(holding)
            enemies_by_clan = {}
            enemy_count = 0
            most_numerous_clan_enemy_count = 0
            most_numerous_clan = None
            for name in holding_state.players:
                clan, rank = self.monitor.get_player_clan_info(name)
                if self.is_friendly(name, clan):
                    continue
                enemies = enemies_by_clan.get(clan)
                if enemies is None:
                    enemies_by_clan[clan] = enemies = set()
                enemies.add(name)
                # if it's a new highest total or the same but with a clan alphabetically earlier (prioritizing clans over unclanned None entries)
                clan_enemy_count = len(enemies)
                enemy_count += clan_enemy_count
                if clan_enemy_count > most_numerous_clan_enemy_count or (clan_enemy_count == most_numerous_clan_enemy_count and (
                        # most numerous is unclanned, or it is a clan and this clan is one alphabetically earlier
                        # (prioritizing clans over unclanned 'None' entries)
                        not most_numerous_clan or (clan and clan < most_numerous_clan))):
                    most_numerous_clan_enemy_count = clan_enemy_count
                    most_numerous_clan = clan
            if enemy_count:
                total_enemies += enemy_count
                if len(enemies_by_clan) == 1:
                    clan, enemies = next(iter(enemies_by_clan.items()))
                    clan_string = self.filter_clan(clan)
                    if clan_string == clan:
                        # unfiltered, fix the case instead
                        clan_string = self.monitor.cased_clan_name.get(clan)
                    if len(enemies) == 1:
                        name = next(iter(enemies))
                        name_string = self.filter_player(name)
                        if name_string == name:
                            # unfiltered, fix the case instead
                            name_string = self.monitor.cased_player_name.get(name)
                        alert = f'{holding_string} has enemy {name_string} from {clan_string}'
                    else:
                        alert = f'{holding_string} has {enemy_count} enemies from {clan_string}'
                else:
                    clan_string = self.filter_clan(most_numerous_clan)
                    if clan_string == most_numerous_clan:
                        # unfiltered, fix the case instead
                        clan_string = self.monitor.cased_clan_name.get(most_numerous_clan)
                    alert = f'{holding_string} has {enemy_count} enemies, mostly from {clan_string}'
                is_warning = True
            else:
                alert = f'{holding_string} is clear'
                is_warning = False
            this_alert_changed = (last_alert != alert)
            if this_alert_changed or (is_warning and all_warnings_on_change):
                if this_alert_changed:
                    any_alert_changed = True
                # this is a new alert, add it to the list to be output
                if is_warning:
                    # just for sorting the messages by enemy count and holding name
                    bisect.insort(prioritized_warnings, (-enemy_count, holding, alert))
                else:
                    # for sorting by holding name
                    bisect.insort(notices, (holding, alert))
                #print(f'CHANGED! "{last_alert}" != {alert}')
                self.holding_alert[holding] = alert
                
        alerts = []
        if any_alert_changed or full_status:
            warnings = [entry[2] for entry in prioritized_warnings]
            notices = [entry[1] for entry in notices]
            #print(f'ALERT CHANGED: {warnings} ____ {notices}')
            if warnings:
                alerts.append(f'WARNING: {oxford_comma_delimited_string(warnings)}')
            # if everything is clear, and either we want a status
            # update or this is indeed new (because a new notice exists)
            if not total_enemies and (full_status or notices):
                alerts.append('NOTICE: all clear')
            elif notices:
                alerts.append(f'NOTICE: {oxford_comma_delimited_string(notices)}')
            # TODO: remove debug divider
            #print('----------------')
        return alerts    
    
    def check_for_changes(self, full_status=False, all_warnings_on_change=False):
        now = datetime.datetime.now()
        changed_proximity, changed_resources = self.monitor.check_for_changes()
        if changed_proximity:
            for holding, player_state in changed_proximity.items():
                # check the new events for 'seen' functionality
                for name, state in player_state.items():
                    present, is_current = state
                    if is_current:
                        # by checking if it's current, we're sure that this is the latest
                        # location, for situations where the player has left multiple holdings
                        # within the contents of a single update.
                        self.seen_players[name] = (now, holding)
        return (now, self._get_alerts(full_status=full_status, all_warnings_on_change=all_warnings_on_change))
        
    # get the status without checking
    def status(self):
        now = datetime.datetime.now()
        return (now, self._get_alerts(full_status=True))