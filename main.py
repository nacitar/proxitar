import api_client
import news_reel_monitor
import alert_bot
import os
import time
import hashlib
SCRIPT_DIRECTORY = os.path.dirname(os.path.realpath(__file__))

# UNKNOWN MESSAGE: A stationary cannon has just been spawned in our city of foo.
LOGIN_RETRY_DELAY = 10
MONITOR_POLL_DELAY = 10
USERNAME="username_goes_here"
PASSWORD="password_goes_here"
PASSWORD_SHA1 = None  # can leave PASSWORD blank and just use this
# move all this into a settings json

arguments = {
    'web_url': 'http://107.155.100.182:50313/spenefett/fwd',
    #'mock_set': {api_client.ApiCategory.LOGIN, api_client.ApiCategory.CLAN},
    'option_set': {
        #api_client.ClientOption.MOCKING_ONLY,
        api_client.ClientOption.PRINT_CLAN_ID,
        api_client.ClientOption.PRINT_SESSION,
        #api_client.ClientOption.PRINT_REQUEST,
        #api_client.ClientOption.PRINT_RESPONSE,
        #api_client.ClientOption.PRINT_MESSAGE,
        #api_client.ClientOption.PRINT_NEWS_REEL,
        #api_client.ClientOption.WRITE_MISSING_MOCKS
    },
    'session_file': os.path.join(SCRIPT_DIRECTORY, 'session.json')
}
api = api_client.ApiClient(**arguments)

while True:
    try:
        if PASSWORD_SHA1 is None:
            PASSWORD_SHA1 = hashlib.sha1(PASSWORD.encode('ascii')).hexdigest().upper()
        else:
            PASSWORD_SHA1 = PASSWORD_SHA1.upper()
        
        if api.load_session() or api.login(USERNAME, PASSWORD_SHA1):
            print('Logged in.')
            api.save_session()
            print(api.get_clan_name())
            monitor = news_reel_monitor.NewsReelMonitor(api)
            bot = alert_bot.AlertBot(monitor)
            while True:
                update_datetime, alerts = bot.check_for_changes(all_warnings_on_change=True)
                #update_datetime, alerts = bot.status()
                if alerts:
                    timestamp = update_datetime.strftime('%Y-%m-%d %H:%M:%S')
                    for alert in alerts:
                        print(f'{timestamp} {alert}')
                time.sleep(MONITOR_POLL_DELAY)
        else:
            print('Failed to login.')
    except api_client.ApiError as error:
        print(f'Disconnected due to ApiError: {error}')
    time.sleep(LOGIN_RETRY_DELAY)

    
#api.set_bank_policy(BankPolicy.NON_ENEMY)
#time.sleep(1)
#api.set_bank_policy(BankPolicy.ALLIES)
#time.sleep(1)
#api.set_guard_policy(GuardPolicy.ENEMY)
#time.sleep(1)
#api.set_guard_policy(GuardPolicy.NON_ALLY)

#print(api.get_bank_policy())
#gp = api.get_guard_policy()
#print(gp)
#api.set_guard_policy(gp)
