#!/usr/bin/env python3

# TODO: how will commands handle incorrectly cased names?  will need to be able to do that, preferably without losing original case in messages.
# TODO: initial 'all clear'? here, or in main?
# TODO: save 'seen' persistently upon changes?

# TODO: commands, reporting/unique players (later), saving 'seen' to disk
# figure out clearing of state after a disconnect (or is that a 'main' thing?)
import news_reel_monitor
import bisect
import datetime
 
UNCLANNED_PLACEHOLDER = 'unclanned'
 
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
    
    def is_friendly(self, name, clan):
        # TODO: fill this in
        return False
    def filter_name(self, name):
        # TODO: offensive/stupid player names
        return name
    def filter_clan(self, clan):
        if clan is None:
            global UNCLANNED_PLACEHOLDER
            return UNCLANNED_PLACEHOLDER
        # TODO: offensive/stupid clan names
        return clan
        
    def _get_alerts(self, full_status, all_warnings_on_change):
        changed_proximity, changed_resources = self.monitor.check_for_changes()
        any_alert_changed = False
        prioritized_warnings = []
        notices = []
        total_enemies = 0
        if full_status:
            all_warnings_on_change = True
        # for simplicity, just always check all holdings... we only report new events anyway,
        # and this is necessary for 'all clear' messages anyway
        for holding in self.monitor.holdings():
            # Get the full holding message
            last_alert = self.holding_alert.get(holding, None)
            if last_alert is None:
                self.holding_alert[holding] = last_alert = f'{holding} is clear'
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
            cased_holding = self.monitor.cased_holding_name.get(holding)
            if enemy_count:
                total_enemies += enemy_count
                if len(enemies_by_clan) == 1:
                    clan, enemies = next(iter(enemies_by_clan.items()))
                    filtered_clan = self.filter_clan(clan)
                    if filtered_clan == clan:
                        # it was unchanged/not filtered.. fix the case
                        clan = self.monitor.cased_clan_name.get(clan)
                    else:
                        clan = filtered_clan  # it was filtered, so use it
                    if len(enemies) == 1:
                        name = self.filter_name(next(iter(enemies)))
                        name = self.monitor.cased_player_name.get(name)
                        alert = f'{cased_holding} has enemy {name} from {clan}'
                    else:
                        alert = f'{cased_holding} has {enemy_count} enemies from {clan}'
                else:
                    filtered_clan = self.filter_clan(most_numerous_clan)
                    if filtered_clan == most_numerous_clan:
                        # it was unchanged/not filtered.. fix the case
                        clan = self.monitor.cased_clan_name.get(most_numerous_clan)
                    else:
                        clan = filtered_clan
                    alert = f'{cased_holding} has {enemy_count} enemies, mostly from {clan}'
                is_warning = True
            else:
                alert = f'{cased_holding} is clear'
                is_warning = False
            this_alert_changed = last_alert != alert
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
        return (now, self._get_alerts(full_status=True, all_warnings_on_change=False))