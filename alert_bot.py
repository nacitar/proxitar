#!/usr/bin/env python3
 
import news_reel_monitor
import bisect
 
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
        
    def get_alerts(self):
        # retrieve info granularly, or just process the holdings, or some combination therein
        changed_proximity, changed_resources = self.monitor.check_for_changes()
        # NOTE: if you wanted to track how long someone was in the city,
        # you can deduce that from changed_proximity.
        # TODO: implement 'seen' with it
        if changed_proximity:
            alert_changed = False
            prioritized_warnings = []
            notices = []
            for holding, player_state in changed_proximity.items():
                # check the new events for 'seen' functionality
                for name, event_times in player_state.items():
                    entry_time, exit_time = event_times
                    if exit_time is not None:
                        # player left
                        self.seen_players[name] = (exit_time, holding)
                    else:
                        # player entered
                        self.seen_players[name] = (entry_time, holding)
                # Get the full holding message
                last_alert = self.holding_alert.get(holding, None)
                if last_alert is None:
                    self.holding_alert[holding] = last_alert = f'{holding} is clear'
                holding_state = self.monitor.holding_state(holding)
                enemies_by_clan = {}
                # use .keys() because we don't care about the entry time
                enemy_count = 0
                most_numerous_clan_count = 0
                most_numerous_clan = None
                for name in holding_state.players.keys():
                    clan, rank = self.monitor.get_player_clan_info(name)
                    # TODO: filter out friendlies here
                    if self.is_friendly(name, clan):
                        continue
                    enemies = enemies_by_clan.get(clan)
                    if enemies is None:
                        enemies_by_clan[clan] = enemies = set()
                    enemies.add(name)
                    # if it's a new highest total or the same but with a clan alphabetically earlier (prioritizing clans over unclanned None entries)
                    enemy_count = len(enemies)
                    if enemy_count > most_numerous_clan_count or (enemy_count == most_numerous_clan_count and (
                            # most numerous is unclanned, or it is a clan and this clan is one alphabetically earlier
                            # (prioritizing clans over unclanned 'None' entries)
                            not most_numerous_clan or (clan and clan < most_numerous_clan))):
                        most_numerous_clan_count = enemy_count
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
                    print(f'CHANGED! "{last_alert}" != {alert}')
                    self.holding_alert[holding] = alert
                    # if any alert at all changed
                    alert_changed = True
            if alert_changed:
                warnings = [entry[2] for entry in prioritized_warnings]
                notices = [entry[1] for entry in notices]
                print(f'ALERT CHANGED: {warnings} ____ {notices}')
                if warnings:
                    full_warning = f'WARNING: {oxford_comma_delimited_string(warnings)}'
                    print(full_warning)
                if notices:
                    full_notice = f'NOTICE: {oxford_comma_delimited_string(notices)}'
                    print(full_notice)
                # TODO: remove debug divider
                print('----------------')