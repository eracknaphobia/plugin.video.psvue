import os, xbmc, xbmcaddon, xbmcgui
import cookielib, requests, urllib


class SONY():
    addon = xbmcaddon.Addon()
    device_id = ''
    localized = addon.getLocalizedString
    login_client_id = '71a7beb8-f21a-47d9-a604-2e71bee24fe0'
    npsso = ''
    password = ''
    req_client_id = 'dee6a88d-c3be-4e17-aec5-1018514cee40'
    req_payload = ''
    ua_android = 'Mozilla/5.0 (Linux; Android 6.0.1; Build/MOB31H; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/44.0.2403.119 Safari/537.36'
    ua_sony = 'com.sony.snei.np.android.sso.share.oauth.versa.USER_AGENT'
    username = ''
    verify = False


    def __init__(self):
        self.device_id = self.addon.getSetting('deviceId')
        self.npsso = self.addon.getSetting('npsso')
        self.password = self.addon.getSetting('password')
        self.req_payload = self.addon.getSetting('reqPayload')
        self.username = self.addon.getSetting('username')



    def check_login(self):
        expired_cookies = True
        addon_profile_path = xbmc.translatePath(self.addon.getAddonInfo('profile'))
        try:
            cj = cookielib.LWPCookieJar()
            cj.load(os.path.join(addon_profile_path, 'cookies.lwp'), ignore_discard=True)
            if self.npsso != '':
                for cookie in cj:
                    if cookie.name == 'npsso':
                        expired_cookies = cookie.is_expired()
                        break
        except:
            pass

        if expired_cookies:
            self.login()


    def login(self):
        if self.username == '':
            dialog = xbmcgui.Dialog()
            self.username = dialog.input(self.localized(30202), type=xbmcgui.INPUT_ALPHANUM)
            if self.username != '':
                self.addon.setSetting(id='username', value=self.username)
            else:
                sys.exit()

        if self.password == '':
            dialog = xbmcgui.Dialog()
            self.password = dialog.input(self.localized(30203), type=xbmcgui.INPUT_ALPHANUM, option=xbmcgui.ALPHANUM_HIDE_INPUT)
            if self.password != '':
                self.addon.setSetting(id='password', value=self.password)
            else:
                sys.exit()

        if self.username != '' and self.password != '':
            url = 'https://auth.api.sonyentertainmentnetwork.com/2.0/ssocookie'
            headers = {"Accept": "*/*",
                       "Content-type": "application/x-www-form-urlencoded",
                       "Origin": "https://id.sonyentertainmentnetwork.com",
                       "Accept-Language": "en-US,en;q=0.8",
                       "Accept-Encoding": "deflate",
                       "User-Agent": self.ua_android,
                       "Connection": "Keep-Alive"
                       }

            payload = 'authentication_type=password&username='+urllib.quote_plus(self.username)+'&password='+urllib.quote_plus(self.password)+'&client_id='+self.login_client_id
            r = requests.post(url, headers=headers, cookies=self.load_cookies(), data=payload, verify=self.verify)
            json_source = r.json()
            self.save_cookies(r.cookies)

            if 'npsso' in json_source:
                npsso = json_source['npsso']
                self.addon.setSetting(id='npsso', value=npsso)
            elif 'authentication_type' in json_source:
                if json_source['authentication_type'] == 'two_step':
                    ticket_uuid = json_source['ticket_uuid']
                    self.two_step_verification(ticket_uuid)
            elif 'error_description' in json_source:
                msg = json_source['error_description']
                self.error_msg(self.localized(30200), msg)
                sys.exit()
            else:
                # Something went wrong during login
                self.error_msg(self.localized(30200), self.localized(30201))
                sys.exit()


    def two_step_verification(self, ticket_uuid):
        dialog = xbmcgui.Dialog()
        code = dialog.input(self.localized(30204), type=xbmcgui.INPUT_ALPHANUM)
        if code == '': sys.exit()

        url = 'https://auth.api.sonyentertainmentnetwork.com/2.0/ssocookie'
        headers = {
            "Accept": "*/*",
            "Content-type": "application/x-www-form-urlencoded",
            "Origin": "https://id.sonyentertainmentnetwork.com",
            "Accept-Language": "en-US,en;q=0.8",
            "Accept-Encoding": "deflate",
            "User-Agent": self.ua_android,
            "Connection": "Keep-Alive",
            "Referer": "https://id.sonyentertainmentnetwork.com/signin/?service_entity=urn:service-entity:psn&ui=pr&service_logo=ps&response_type=code&scope=psn:s2s&client_id="+self.req_client_id+"&request_locale=en_US&redirect_uri=https://io.playstation.com/playstation/psn/acceptLogin&error=login_required&error_code=4165&error_description=User+is+not+authenticated"
        }

        payload = 'authentication_type=two_step&ticket_uuid='+ticket_uuid+'&code='+code+'&client_id='+self.login_client_id
        r = requests.post(url, headers=headers, cookies=self.load_cookies(), data=payload, verify=self.verify)
        json_source = r.json()
        self.save_cookies(r.cookies)

        if 'npsso' in json_source:
            npsso = json_source['npsso']
            self.addon.setSetting(id='npsso', value=npsso)
        elif 'error_description' in json_source:
            msg = json_source['error_description']
            self.error_msg(self.localized(30200), msg)
            sys.exit()
        else:
            # Something went wrong during login
            self.error_msg(self.localized(30200), self.localized(30201))
            sys.exit()


    def get_grant_code(self):
        url = 'https://auth.api.sonyentertainmentnetwork.com/2.0/oauth/authorize'
        url += '?response_type=code'
        url += '&client_id=' + self.req_client_id
        url += '&redirect_uri=https%3A%2F%2Fthemis.dl.playstation.net%2Fthemis%2Fzartan%2Fredirect.html'
        url += '&scope=psn%3As2s'
        url += '&signInOnly=true'
        url += '&service_entity=urn%3Aservice-entity%3Anp'
        url += '&prompt=none'
        url += '&duid=' + self.device_id

        headers = {
            "Accept-Encoding": "gzip",
            "User-Agent": self.ua_sony,
            "Connection": "Keep-Alive",
        }

        code = ''
        r = requests.get(url, headers=headers, allow_redirects=False, cookies=self.load_cookies(), verify=self.verify)
        if 'X-NP-GRANT-CODE' in r.headers:
            code = r.headers['X-NP-GRANT-CODE']
        else:
            self.error_msg('Auth Failed','Could not retrieve grant code')
            sys.exit()

        return code


    def reauthorize_device(self):
        url = 'https://sentv-user-auth.totsuko.tv/sentv_user_auth/ws/oauth2/token'
        url += '?device_type_id=android_tablet'
        url += '&device_id=' + self.device_id
        url += '&code=' + self.get_grant_code()
        url += '&redirect_uri=https%3A%2F%2Fthemis.dl.playstation.net%2Fthemis%2Fzartan%2Fredirect.html'

        headers = {
            'Origin': 'https://themis.dl.playstation.net',
            'User-Agent': self.ua_android,
            'reauth': '1',
            'reqPayload': self.addon.getSetting(id='reqPayload'),
            'Accept': '*/*',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }

        r = requests.get(url, headers=headers, verify=self.verify)
        if 'reqPayload' in r.headers:
            req_payload = str(r.headers['reqPayload'])
            self.addon.setSetting(id='reqPayload', value=req_payload)
        else:
            self.error_msg('Auth Failed','Could not retrieve the reqpayload')
            sys.exit()


    def get_profiles():
        url = 'https://sentv-user-ext.totsuko.tv/sentv_user_ext/ws/v2/profile/ids'
        headers = {
            'User-Agent': self.ua_android,
            'reqPayload': self.req_payload,
            'Accept': '*/*',
            'Origin': 'https://themis.dl.playstation.net',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }

        r = requests.get(url, headers=headers, verify=self.verify)
        if 'body' in r.json() and 'profiles' in r.json()['body']:
            profiles = r.json()['body']['profiles']
            prof_dict = {}
            prof_list = []
            for profile in profiles:
                xbmc.log(str(profile['profile_id']) + ' ' + str(profile['profile_name']))
                prof_dict[str(profile['profile_name'])] = str(profile['profile_id'])
                prof_list.append(str(profile['profile_name']))

            dialog = xbmcgui.Dialog()
            ret = dialog.select('Choose Profile', prof_list)
            if ret >= 0:
                set_profile(prof_dict[prof_list[ret]])
            else:
                sys.exit()
        else:
            self.error_msg('Profile Not Found', 'Your profile list could not be retrieved.')
            sys.exit()


    def save_cookies(self, cookiejar):
        addon_profile_path = xbmc.translatePath(self.addon.getAddonInfo('profile'))
        filename = os.path.join(addon_profile_path, 'cookies.lwp')
        lwp_cookiejar = cookielib.LWPCookieJar()
        for c in cookiejar:
            args = dict(vars(c).items())
            args['rest'] = args['_rest']
            del args['_rest']
            c = cookielib.Cookie(**args)
            lwp_cookiejar.set_cookie(c)
        lwp_cookiejar.save(filename, ignore_discard=True)


    def load_cookies(self):
        addon_profile_path = xbmc.translatePath(self.addon.getAddonInfo('profile'))
        filename = os.path.join(addon_profile_path, 'cookies.lwp')
        lwp_cookiejar = cookielib.LWPCookieJar()
        try:
            lwp_cookiejar.load(filename, ignore_discard=True)
        except:
            pass

        return lwp_cookiejar


    def error_msg(self, title, msg):
        dialog = xbmcgui.Dialog()
        dialog.notification(title, msg, xbmcgui.NOTIFICATION_INFO, 5000)
