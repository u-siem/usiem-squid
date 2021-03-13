use reqwest;
use std::env;
use usiem::events::{SiemLog};
use usiem::events::field::{SiemIp,SiemField};
use usiem::events::webproxy::WebProxyRuleCategory;
use usiem::events::field_dictionary;
use usiem_squid::squid;
use usiem_squid::squidguard;
#[test]
fn test_squid_integration() {
    let out_dir = env::var("CI_CD").unwrap_or(String::from(""));
    if out_dir == "" {
        return;
    }
    let client = reqwest::blocking::Client::builder()
        .proxy(reqwest::Proxy::http("http://127.0.0.1:3128").unwrap())
        .build()
        .unwrap();
    let res = client.get("http://127.0.0.1:80/squidGuard.log").send().unwrap();

    if !res.status().is_success() {
        panic!("SquidGuard must be active");
    }

    // HACK PAGE
    let hack_url = "http://hackpage.com/random-stuff/and-random.html?param_1=value_1&param_2=value_2";
    get_url(hack_url, &client);

    let lingerie_url = "http://lingeriepage.com/random-stuff/and-random.html?param_1=value_1&param_2=value_2";
    get_url(lingerie_url, &client);

    let porn_url = "http://pornpage.com/random-stuff/and-random.html?param_1=value_1&param_2=value_2";
    get_url(porn_url, &client);

    let anon_url = "http://anonpage.com/random-stuff/and-random.html?param_1=value_1&param_2=value_2";
    get_url(anon_url, &client);


    let res = client.get("http://127.0.0.1:80/access.log").send().unwrap();
    if !res.status().is_success() {
        panic!("Squid must be active");
    }
    let access_text = res.text().unwrap();
    let split = access_text.split("\n");
    let access_text: Vec<&str> = split.collect();

    let denied_text1 = access_text.get(1).unwrap();
    let denied_text2 = access_text.get(2).unwrap();
    let denied_text3 = access_text.get(3).unwrap();
    let denied_text4 = access_text.get(4).unwrap();

    test_denied_squid(denied_text1);
    test_denied_squid(denied_text2);
    test_denied_squid(denied_text3);
    test_denied_squid(denied_text4);

    get_url(anon_url, &client);

    let res = client.get("http://127.0.0.1:80/deny.log").send().unwrap();
    if !res.status().is_success() {
        panic!("The URL deny.log MUST not be blocked. Error in configuration");
    }
    let deny_text = res.text().unwrap();
    let split = deny_text.split("\n");
    let deny_text: Vec<&str> = split.collect();

    let deny_hack = deny_text.get(0).unwrap();
    test_denied_hack(deny_hack);
    let deny_lingerie = deny_text.get(1).unwrap();
    test_denied_lingerie(deny_lingerie);
    let deny_porn = deny_text.get(2).unwrap();
    test_denied_porn(deny_porn);
    let deny_anonvpn = deny_text.get(3).unwrap();
    test_denied_anon(deny_anonvpn);
    
}


fn test_denied_hack(denied_text : &str) {
    //2021-03-13 19:46:49 [21] Request(default/hacking/-) http://hackpage.com/random-stuff/and-random.html?param_1=value_1&param_2=value_2 172.17.0.1/172.17.0.1 - GET REDIRECT
    let log = SiemLog::new(denied_text.to_string(), 0, SiemIp::V4(0));
    match squidguard::parse_log(log) {
        Ok(log) => {
            assert_eq!(log.field(field_dictionary::DESTINATION_IP), Some(&SiemField::IP(SiemIp::from_ip_str("0.0.0.0").expect("Must work"))));
            assert_eq!(log.field(field_dictionary::EVENT_OUTCOME), Some(&SiemField::from_str("BLOCK")));
            assert_eq!(log.field(field_dictionary::HTTP_RESPONSE_STATUS_CODE), Some(&SiemField::U64(503)));
            assert_eq!(log.field(field_dictionary::URL_DOMAIN), Some(&SiemField::from_str("hackpage.com")));
            assert_eq!(log.field(field_dictionary::DESTINATION_PORT), Some(&SiemField::U64(80)));
            assert_eq!(log.field(field_dictionary::DESTINATION_BYTES), Some(&SiemField::U64(0)));
            assert_eq!(log.field(field_dictionary::RULE_CATEGORY), Some(&SiemField::from_str(WebProxyRuleCategory::Hacking.to_string())));
            assert_eq!(log.field(field_dictionary::HTTP_REQUEST_METHOD), Some(&SiemField::from_str("GET")));
            assert_eq!(log.field(field_dictionary::URL_PATH), Some(&SiemField::from_str("/random-stuff/and-random.html")));
            assert_eq!(log.field(field_dictionary::URL_QUERY), Some(&SiemField::from_str("?param_1=value_1&param_2=value_2")));
        },
        Err(_) => {
            panic!("Cannot parse log")
        }
    }
}

fn test_denied_lingerie(denied_text : &str) {
    //2021-03-13 19:46:49 [21] Request(default/lingerie/-) http://lingeriepage.com/random-stuff/and-random.html?param_1=value_1&param_2=value_2 172.17.0.1/172.17.0.1 - GET REDIRECT
    let log = SiemLog::new(denied_text.to_string(), 0, SiemIp::V4(0));
    match squidguard::parse_log(log) {
        Ok(log) => {
            assert_eq!(log.field(field_dictionary::DESTINATION_IP), Some(&SiemField::IP(SiemIp::from_ip_str("0.0.0.0").expect("Must work"))));
            assert_eq!(log.field(field_dictionary::EVENT_OUTCOME), Some(&SiemField::from_str("BLOCK")));
            assert_eq!(log.field(field_dictionary::HTTP_RESPONSE_STATUS_CODE), Some(&SiemField::U64(503)));
            assert_eq!(log.field(field_dictionary::URL_DOMAIN), Some(&SiemField::from_str("lingeriepage.com")));
            assert_eq!(log.field(field_dictionary::DESTINATION_PORT), Some(&SiemField::U64(80)));
            assert_eq!(log.field(field_dictionary::DESTINATION_BYTES), Some(&SiemField::U64(0)));
            assert_eq!(log.field(field_dictionary::RULE_CATEGORY), Some(&SiemField::from_str(WebProxyRuleCategory::IntimateApparel.to_string())));
            assert_eq!(log.field(field_dictionary::HTTP_REQUEST_METHOD), Some(&SiemField::from_str("GET")));
            assert_eq!(log.field(field_dictionary::URL_PATH), Some(&SiemField::from_str("/random-stuff/and-random.html")));
            assert_eq!(log.field(field_dictionary::URL_QUERY), Some(&SiemField::from_str("?param_1=value_1&param_2=value_2")));
        },
        Err(_) => {
            panic!("Cannot parse log")
        }
    }
}

fn test_denied_porn(denied_text : &str) {
    //2021-03-13 19:46:49 [21] Request(default/porn/-) http://pornpage.com/random-stuff/and-random.html?param_1=value_1&param_2=value_2 172.17.0.1/172.17.0.1 - GET REDIRECT
    let log = SiemLog::new(denied_text.to_string(), 0, SiemIp::V4(0));
    match squidguard::parse_log(log) {
        Ok(log) => {
            assert_eq!(log.field(field_dictionary::DESTINATION_IP), Some(&SiemField::IP(SiemIp::from_ip_str("0.0.0.0").expect("Must work"))));
            assert_eq!(log.field(field_dictionary::EVENT_OUTCOME), Some(&SiemField::from_str("BLOCK")));
            assert_eq!(log.field(field_dictionary::HTTP_RESPONSE_STATUS_CODE), Some(&SiemField::U64(503)));
            assert_eq!(log.field(field_dictionary::URL_DOMAIN), Some(&SiemField::from_str("pornpage.com")));
            assert_eq!(log.field(field_dictionary::DESTINATION_PORT), Some(&SiemField::U64(80)));
            assert_eq!(log.field(field_dictionary::DESTINATION_BYTES), Some(&SiemField::U64(0)));
            assert_eq!(log.field(field_dictionary::RULE_CATEGORY), Some(&SiemField::from_str(WebProxyRuleCategory::Pornography.to_string())));
            assert_eq!(log.field(field_dictionary::HTTP_REQUEST_METHOD), Some(&SiemField::from_str("GET")));
            assert_eq!(log.field(field_dictionary::URL_PATH), Some(&SiemField::from_str("/random-stuff/and-random.html")));
            assert_eq!(log.field(field_dictionary::URL_QUERY), Some(&SiemField::from_str("?param_1=value_1&param_2=value_2")));
        },
        Err(_) => {
            panic!("Cannot parse log")
        }
    }
}

fn test_denied_anon(denied_text : &str) {
    //2021-03-13 19:46:49 [21] Request(default/anonvpn/-) http://anonpage.com/random-stuff/and-random.html?param_1=value_1&param_2=value_2 172.17.0.1/172.17.0.1 - GET REDIRECT
    let log = SiemLog::new(denied_text.to_string(), 0, SiemIp::V4(0));
    match squidguard::parse_log(log) {
        Ok(log) => {
            assert_eq!(log.field(field_dictionary::DESTINATION_IP), Some(&SiemField::IP(SiemIp::from_ip_str("0.0.0.0").expect("Must work"))));
            assert_eq!(log.field(field_dictionary::EVENT_OUTCOME), Some(&SiemField::from_str("BLOCK")));
            assert_eq!(log.field(field_dictionary::HTTP_RESPONSE_STATUS_CODE), Some(&SiemField::U64(503)));
            assert_eq!(log.field(field_dictionary::URL_DOMAIN), Some(&SiemField::from_str("anonpage.com")));
            assert_eq!(log.field(field_dictionary::DESTINATION_PORT), Some(&SiemField::U64(80)));
            assert_eq!(log.field(field_dictionary::DESTINATION_BYTES), Some(&SiemField::U64(0)));
            assert_eq!(log.field(field_dictionary::RULE_CATEGORY), Some(&SiemField::from_str(WebProxyRuleCategory::ProxyAvoidance.to_string())));
            assert_eq!(log.field(field_dictionary::HTTP_REQUEST_METHOD), Some(&SiemField::from_str("GET")));
            assert_eq!(log.field(field_dictionary::URL_PATH), Some(&SiemField::from_str("/random-stuff/and-random.html")));
            assert_eq!(log.field(field_dictionary::URL_QUERY), Some(&SiemField::from_str("?param_1=value_1&param_2=value_2")));
        },
        Err(_) => {
            panic!("Cannot parse log")
        }
    }
}

fn test_denied_squid(denied_text : &str) {
    let log = SiemLog::new(denied_text.to_string(), 0, SiemIp::V4(0));
    match squid::parse_log(log) {
        Ok(log) => {
            assert_eq!(log.field(field_dictionary::DESTINATION_IP), Some(&SiemField::IP(SiemIp::from_ip_str("127.0.0.1").expect("Must work"))));
            assert_eq!(log.field(field_dictionary::EVENT_OUTCOME), Some(&SiemField::from_str("BLOCK")));
            assert_eq!(log.field(field_dictionary::HTTP_RESPONSE_STATUS_CODE), Some(&SiemField::U64(403)));
            assert_eq!(log.field(field_dictionary::URL_DOMAIN), Some(&SiemField::from_str("127.0.0.1")));
            assert_eq!(log.field(field_dictionary::DESTINATION_PORT), Some(&SiemField::U64(80)));
            assert_eq!(log.field(field_dictionary::DESTINATION_BYTES), Some(&SiemField::U64(613)));
        },
        Err(_) => {
            panic!("Cannot parse log")
        }
    }
}

fn get_url(url : &'static str, client : &reqwest::blocking::Client) {
    let res = client.get(url).send().unwrap();
    if res.status().is_success() {
        panic!("The URL {} MUST be blocked. Error in configuration", url);
    }
}