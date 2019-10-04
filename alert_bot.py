#!/usr/bin/env python3
 
import news_reel_monitor
import bisect
import datetime
 
UNCLANNED_PLACEHOLDER = 'unclanned'
 
# WARNING: Holding has enemy FirstName LastName from ClanName
# WARNING: Holding has X enemies from ClanName
# WARNING: Holding has X enemies, mostly from ClanName
# combined like WARNING: Message1, Message2, Message3, and MessageN

def oxford_comma_delimited_string(entries):
    count = len(entries)
    if count:
        if count == 1:
            return entries[0]
        return f"{', '.join(entries[:-1])}, and {entries[-1]}"
    return ''

# TODO: lower to normal case player mappings
# TODO: currently only shows changed warnings, but should we re-report
# other non-empty holdings too, when that happens?
class AlertBot(object): 
    def __init__(self, monitor):
        self.holding_alert = {}
        self.monitor = monitor
        self.seen_players = {}
        # TODO: the 'unique' stuff
        # self.players_by_holding = {}
    
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
        
    @staticmethod
    def format_datetime(value):
        return value.strftime('%Y-%m-%d %H:%M:%S')

    # TODO: alerting rules for 'status' command
    # TODO: need 'all clear' message!
    def get_alerts(self):
        # retrieve info granularly, or just process the holdings, or some combination therein
        changed_proximity, changed_resources = self.monitor.check_for_changes()
        # TODO: implement 'seen' with it
        now = datetime.datetime.now()
        if changed_proximity:
            alert_changed = False
            prioritized_warnings = []
            notices = []
            for holding, player_state in changed_proximity.items():
                # check the new events for 'seen' functionality
                for name in player_state.keys():
                    location = self.monitor.player_holding.get(name)
                    if location is not None:
                        # If the player is still in one of the cities, use that holding for the state
                        self.seen_players[name] = (now, location)
                    else:
                        # Set last seen location to the holding that was left. In
                        # a "leave, enter different holding, leave that" scenario
                        # the holdings will overwrite each other and what will be
                        # reported for the player is the last one iterated over in
                        # the outer changed_proximity.items() loop.
                        self.seen_players[name] = (now, holding)
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
                    # TODO: filter out friendlies here
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
                    if len(enemies_by_clan) == 1:
                        clan, enemies = next(iter(enemies_by_clan.items()))
                        clan = self.filter_clan(clan)
                        if len(enemies) == 1:
                            name = self.filter_name(next(iter(enemies)))
                            alert = f'{holding} has enemy {name} from {clan}'
                        else:
                            alert = f'{holding} has {enemy_count} enemies from {clan}'
                    else:
                        clan = self.filter_clan(most_numerous_clan)
                        alert = f'{holding} has {enemy_count} enemies, mostly from {clan}'
                    # just for sorting the messages by enemy count and holding name
                    bisect.insort(prioritized_warnings, (-enemy_count, holding, alert))
                else:
                    alert = f'{holding} is clear'
                    bisect.insort(notices, (holding, alert))
                    
                if last_alert != alert:
                    #print(f'CHANGED! "{last_alert}" != {alert}')
                    self.holding_alert[holding] = alert
                    # if any alert at all changed
                    alert_changed = True
            if alert_changed:
                warnings = [entry[2] for entry in prioritized_warnings]
                notices = [entry[1] for entry in notices]
                #print(f'ALERT CHANGED: {warnings} ____ {notices}')
                timestamp = now.strftime('%Y-%m-%d %H:%M:%S')
                if warnings:
                    full_warning = f'{timestamp} WARNING: {oxford_comma_delimited_string(warnings)}'
                    print(full_warning)
                if notices:
                    full_notice = f'{timestamp} NOTICE: {oxford_comma_delimited_string(notices)}'
                    print(full_notice)
                # TODO: remove debug divider
                print('----------------')