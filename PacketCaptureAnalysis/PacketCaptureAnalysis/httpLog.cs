public class httpLog
{
    public string ts { get; set; }
    public string uid { get; set; }
    public string id_orig_h { get; set; }
    public int id_orig_p { get; set; }
    public string id_resp_h { get; set; }
    public int id_resp_p { get; set; }
    public int trans_depth { get; set; }
    public string method { get; set; }
    public string host { get; set; }
    public string uri { get; set; }
    public string referrer { get; set; }
    public string user_agent { get; set; }
    public int request_body_len { get; set; }
    public int response_body_len { get; set; }
    public int status_code { get; set; }
    public string status_msg { get; set; }
    public string info_code { get; set; }
    public string info_msg { get; set; }
    public string filename { get; set; }
    public string tags { get; set; }
    public string username { get; set; }
    public string password { get; set; }
    public string proxied { get; set; }
    public string orig_fuids { get; set; }
    public string orig_mime_types { get; set; }
    public string resp_fuids { get; set; }
    public string resp_mime_types { get; set; }
}
