from pathlib import Path
import json,sys,time,urllib.error,urllib.parse,urllib.request
sys.path.insert(0,'/usr/local/lib/crowdsec-1key-bot')
import crowdsec_bot as bot
bot.load_settings('/etc/crowdsec/crowdsec-1key-bot.json')
checks=[]
for method,parameters in [('getMe',{}),('getChat',{'chat_id':bot.ADMIN_CHAT_ID})]:
    request=urllib.request.Request(bot.TG_API_BASE.rstrip('/')+'/'+method,data=urllib.parse.urlencode(parameters).encode(),method='POST')
    started=time.monotonic()
    try:
        with urllib.request.urlopen(request,timeout=10) as response:
            result=json.load(response)
            http_status=response.status
    except urllib.error.HTTPError as error:
        raise SystemExit('Read-only Telegram API check failed with HTTP '+str(error.code)) from None
    except Exception:
        raise SystemExit('Read-only Telegram API check did not complete') from None
    assert result.get('ok') is True
    if method=='getMe':assert result['result']['is_bot'] is True and str(result['result']['id'])==bot.BOT_TOKEN.split(':',1)[0]
    else:assert str(result['result']['id'])==str(bot.ADMIN_CHAT_ID)
    checks.append({'method':method,'http_status':http_status,'ok':True,'seconds':round(time.monotonic()-started,3)})
print(json.dumps({'checked_at':time.time(),'checks':checks,'messages_sent':0,'poll_requests':0,'scope':'Bot identity and configured-chat access; no delivery or user-button test.'},indent=2))
