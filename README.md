public bool Authenticate()
{
    var FacebookAppId = ConfigurationManager.AppSettings["FACEBOOK_APPID"];
    var FacebookAppSecret = ConfigurationManager.AppSettings["FACEBOOK_SECRET"];


    var cookie = Request.Cookies["fbs_" + FacebookAppId];

    if (cookie == null) return false;
                
    var data = cookie.Value;

    Func<string, KeyValuePair<string, string>> toNameValue = m =>
    {
        var nameValue = m.Split('=');
        return new KeyValuePair<string, string>(nameValue[0], nameValue[1]);
    };

    data = data.Substring(1, data.Length - 2);

    var keys = data.Split('&').Select(toNameValue).OrderBy(m => m.Key);

    var payload = string.Join("", keys.Where(m => m.Key != "sig").Select(m => string.Format("{0}={1}", m.Key, m.Value)));
    payload = payload + FacebookAppSecret;

    var hash = payload.ComputeMD5Hash();
    var sig = keys.ToDictionary(m => m.Key)["sig"];
    var success = sig.Value == hash;
    return success;
}
