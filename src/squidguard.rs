use std::borrow::Cow;
use usiem::components::common::LogParsingError;
use usiem::events::common::{HttpMethod, WebProtocol};
use usiem::events::field::{SiemField, SiemIp};
use usiem::events::field_dictionary;
use usiem::events::webproxy::{WebProxyEvent, WebProxyOutcome, WebProxyRuleCategory};
use usiem::events::{SiemEvent, SiemLog};
use chrono::{TimeZone, Utc};

pub fn parse_log(log: SiemLog) -> Result<SiemLog, LogParsingError> {
    let log_line = log.message();

    let request_pos = match log_line.find(" Request(") {
        Some(pos) => pos,
        None => return Err(LogParsingError::NoValidParser(log)),
    };

    let mut log_parsed = Vec::with_capacity(16);
    let mut last_pos = 0;

    let log_header = &log_line[..request_pos];

    for (pos, c) in log_header.char_indices() {
        if c == ' ' {
            if (last_pos + 1) <= pos {
                log_parsed.push(&log_header[last_pos..pos]);
            }
            last_pos = pos + 1;
        }
    }
    log_parsed.push(&log_header[last_pos..]);
    
    if log_parsed.len() < 3 {
        return Err(LogParsingError::ParserError(log));
    }
    let (date, hours) = match (log_parsed.get(log_parsed.len() - 3),log_parsed.get(log_parsed.len() - 2)) {
        (Some(date),Some(hour)) => (date,hour),
        _ => return Err(LogParsingError::ParserError(log))
    };
    let event_created = match Utc.datetime_from_str(&format!("{} {}",date,hours)[..], "%Y-%m-%d %H:%M:%S") {
        Ok(timestamp) => timestamp.timestamp_millis(),
        Err(_err) => return Err(LogParsingError::ParserError(log)),
    };

    let mut log_parsed = Vec::with_capacity(16);

    let log_body = &log_line[request_pos + 1..];
    let mut last_pos = 0;
    for (pos, c) in log_body.char_indices() {
        if c == ' ' {
            if (last_pos + 1) <= pos {
                log_parsed.push(&log_body[last_pos..pos]);
            }
            last_pos = pos + 1;
        }
    }
    log_parsed.push(&log_body[last_pos..]);

    let source_ip = match log_parsed.get(2) {
        Some(source_ip) => {
            match source_ip.find("/") {
                Some(pos) => &source_ip[..pos],
                None => return Err(LogParsingError::ParserError(log))
            }
        },
        None => return Err(LogParsingError::ParserError(log))
    };

    let source_ip = match SiemIp::from_ip_str(source_ip) {
        Ok(ip) => ip,
        Err(_) => return Err(LogParsingError::NoValidParser(log)),
    };
    let destination_ip = SiemIp::V4(0);

    

    let url_parsed = match log_parsed.get(1){
        Some(v) => v,
        None => return Err(LogParsingError::ParserError(log))
    };
    let (protocol, domain, url, destination_port) = match parse_url(url_parsed) {
        Ok(data) => data,
        Err(_) => return Err(LogParsingError::ParserError(log)),
    };

    let user_name = match log_parsed.get(3) {
        Some(user) => {
            match *user {
                "-" => Cow::Borrowed(""),
                usr => Cow::Owned(usr.to_string())
            }
        },
        None => return Err(LogParsingError::ParserError(log))
    };

    let http_method = match log_parsed.get(4) {
        Some(method) => HttpMethod::from_str(method),
        None => return Err(LogParsingError::ParserError(log))
    };

    let mut log = SiemLog::new(
        log_line.to_string(),
        log.event_received(),
        log.origin().clone(),
    );
    

    let (_rule_ruleset, rule_name) = match log_parsed.get(0) {
        Some(cat) => {
            match parse_rule(cat) {
                Ok((v1,v2)) => (v1,v2),
                Err(_) => return Err(LogParsingError::ParserError(log))
            }
        },
        None => return Err(LogParsingError::ParserError(log))
    };

    let rule_category = rule_category(rule_name);


    log.set_event_created(event_created);
    log.set_event(SiemEvent::WebProxy(WebProxyEvent {
        source_ip,
        destination_ip,
        destination_port,
        domain: Cow::Owned(domain.to_string()),
        url: Cow::Owned(url.to_string()),
        http_method,
        http_code : 503,
        mime_type : Cow::Borrowed(""),
        in_bytes : 0,
        out_bytes: 0,
        protocol: parse_protocol(protocol),
        rule_name: Some(Cow::Owned(rule_name.to_string())),
        rule_category: Some(rule_category),
        user_name,
        outcome: WebProxyOutcome::BLOCK,
    }));
    match log_parsed[1].parse::<u64>() {
        Ok(v) => {
            log.add_field(field_dictionary::NETWORK_DURATION, SiemField::U64(v));
        }
        Err(_) => {}
    }

    return Ok(log);
}

/// Categories based on http://www.shallalist.de/categories.html
pub fn rule_category(text: &str) -> WebProxyRuleCategory {
    if text.contains("automobile"){
        return WebProxyRuleCategory::Vehicles
    }else if text.contains("finance"){
        return WebProxyRuleCategory::Finance
    }else if text.contains("hobby"){
        return WebProxyRuleCategory::PersonalSites
    }
    
    match text {
        "adv" => WebProxyRuleCategory::Spam,
        "aggressive" => WebProxyRuleCategory::QuestionableLegality,
        "alcohol" => WebProxyRuleCategory::Alcohol,
        "anonvpn" => WebProxyRuleCategory::ProxyAvoidance,
        "chat" => WebProxyRuleCategory::OnlineChat,
        "costtraps" => WebProxyRuleCategory::Phishing,
        "dating" => WebProxyRuleCategory::PersonalsDating,
        "downloads" => WebProxyRuleCategory::P2P,
        "drugs" => WebProxyRuleCategory::Marijuana,
        "dynamic" => WebProxyRuleCategory::DynamicDNSHost,
        "education/schools" => WebProxyRuleCategory::Education,
        "fortunetelling" => WebProxyRuleCategory::AlternativeSpirituality,
        "forum" => WebProxyRuleCategory::Forums,
        "gamble" => WebProxyRuleCategory::Gambling,
        "government" => WebProxyRuleCategory::Government,
        "hacking" => WebProxyRuleCategory::Hacking,
        "homestyle" => WebProxyRuleCategory::PersonalSites,
        "hospitals" => WebProxyRuleCategory::Health,
        "imagehosting" => WebProxyRuleCategory::WebHosting,
        "isp" => WebProxyRuleCategory::InternetTelephony,
        "jobsearch" => WebProxyRuleCategory::JobSearch,
        "library" => WebProxyRuleCategory::Education,
        "military" => WebProxyRuleCategory::Military,
        "movies" => WebProxyRuleCategory::Education,
        "music" => WebProxyRuleCategory::P2P,
        "news" => WebProxyRuleCategory::News,
        "podcasts" => WebProxyRuleCategory::RadioAudioStreams,
        "politics" => WebProxyRuleCategory::PoliticalAdvocacy,
        "porn" => WebProxyRuleCategory::Pornography,
        "radiotv" => WebProxyRuleCategory::RadioAudioStreams,
        "recreation/humor" => WebProxyRuleCategory::HumorJokes,
        "recreation/martialarts" => WebProxyRuleCategory::Sports,
        "recreation/restaurants" => WebProxyRuleCategory::Restaurants,
        "recreation/sports" => WebProxyRuleCategory::Sports,
        "recreation/travel" => WebProxyRuleCategory::Travel,
        "recreation/wellness" => WebProxyRuleCategory::Health,
        "redirector" => WebProxyRuleCategory::URLShorteners,
        "religion" => WebProxyRuleCategory::Religion,
        "remotecontrol" => WebProxyRuleCategory::RemoteAccess,
        "ringtones" => WebProxyRuleCategory::InternetTelephony,
        "science/astronomy" => WebProxyRuleCategory::Education,
        "science/chemistry" => WebProxyRuleCategory::Education,
        "searchengines" => WebProxyRuleCategory::SearchEngines,
        "sex/lingerie" => WebProxyRuleCategory::IntimateApparel,
        "shopping" => WebProxyRuleCategory::Shopping,
        "socialnet" => WebProxyRuleCategory::SocialNetworking,
        "spyware" => WebProxyRuleCategory::MaliciousSources,
        "tracker" => WebProxyRuleCategory::WebAds,
        "updatesites" => WebProxyRuleCategory::SoftwareDownloads,
        "urlshortener" => WebProxyRuleCategory::URLShorteners,
        "violence" => WebProxyRuleCategory::Violence,
        "warez" => WebProxyRuleCategory::CopyrightConcerns,
        "weapons" => WebProxyRuleCategory::Weapons,
        "webmail" => WebProxyRuleCategory::Email,
        "webphone" => WebProxyRuleCategory::OnlineChat,
        "webradio" => WebProxyRuleCategory::RadioAudioStreams,
        "webtv" => WebProxyRuleCategory::VideoStreams,
        _ => WebProxyRuleCategory::Uncategorized,
    }
}

pub fn parse_outcome(text: &str) -> WebProxyOutcome {
    match text {
        "NONE" => WebProxyOutcome::BLOCK,
        _ => WebProxyOutcome::ALLOW,
    }
}

pub fn parse_protocol(text: &str) -> WebProtocol {
    match text {
        "http" => WebProtocol::HTTP,
        "https" => WebProtocol::HTTPS,
        "ftp" => WebProtocol::FTP,
        "ws" => WebProtocol::WS,
        "wss" => WebProtocol::WSS,
        _ => WebProtocol::UNKNOWN(text.to_owned()),
    }
}


pub fn http_method(method: &str) -> HttpMethod {
    match method {
        "GET" => HttpMethod::GET,
        "POST" => HttpMethod::POST,
        "PUT" => HttpMethod::PUT,
        "PATCH" => HttpMethod::PATCH,
        "OPTIONS" => HttpMethod::OPTIONS,
        "CONNECT" => HttpMethod::CONNECT,
        _ => HttpMethod::UNKNOWN(method.to_uppercase()),
    }
}

pub fn parse_rule<'a>(val: &'a str) -> Result<(&'a str,&'a str), &'static str> {
    let start_pos = match val.find("("){
        Some(pos) => pos,
        None => return Err("")
    };
    let cat_end = match val[start_pos..].find("/") {
        Some(pos) => pos + start_pos,
        None => return Err("")
    };
    let cat_ruleset = &val[start_pos + 1..cat_end];
    let subcat_end = match val[cat_end + 1..].find("/") {
        Some(pos) => pos + cat_end + 1,
        None => return Err("")
    };
    let subcat = &val[cat_end + 1..subcat_end];
    Ok((cat_ruleset, subcat))
}

pub fn parse_url<'a>(url: &'a str) -> Result<(&'a str, &'a str, &'a str, u16), &'static str> {
    let (protocol, sliced_url) = match url.find("://") {
        Some(pos) => (&url[0..pos], &url[pos + 3..]),
        None => ("", url),
    };
    let (domain, url) = match sliced_url.find("/") {
        Some(pos) => (&sliced_url[..pos], &sliced_url[pos..]),
        None => (sliced_url, "/"),
    };
    let (domain, port) = match domain.find(":") {
        Some(pos) => (&domain[..pos], &domain[pos + 1..]),
        None => (domain, "0"),
    };
    let port = match port {
        "0" => translate_protocol_to_port(protocol),
        _ => match port.parse::<u16>() {
            Ok(v) => v,
            Err(_) => return Err("Error parsing port"),
        },
    };
    Ok((protocol, domain, url, port))
}

pub fn translate_protocol_to_port(protocol: &str) -> u16 {
    if protocol == "http" {
        return 80;
    } else if protocol == "https" {
        return 443;
    } else if protocol == "ftp" {
        return 21;
    } else {
        return 0;
    }
}

pub fn destination_ip_from_squid<'a>(text: &'a str) -> Result<(&'a str, &'a str), &'static str> {
    match text.find("/") {
        Some(p) => Ok((&text[..p], &text[p + 1..])),
        None => Err(""),
    }
}


#[cfg(test)]
mod test {
    use usiem::events::{SiemLog};
    use usiem::events::field::{SiemIp,SiemField};
    use usiem::events::field_dictionary;
    #[test]
    fn test_log_from_file() {
        let log = "2021-02-14 00:02:33 [26] Request(default/porn/-) pornpage.com:443 172.17.0.1/172.17.0.1 - CONNECT REDIRECT";
        let log = SiemLog::new(log.to_string(), 0, SiemIp::V4(0));
        match super::parse_log(log) {
            Ok(log) => {
                assert_eq!(log.field(field_dictionary::SOURCE_IP), Some(&SiemField::IP(SiemIp::from_ip_str("172.17.0.1").expect("Must work"))));
                assert_eq!(log.field(field_dictionary::DESTINATION_IP), Some(&SiemField::IP(SiemIp::from_ip_str("0.0.0.0").expect("Must work"))));
                assert_eq!(log.field(field_dictionary::EVENT_OUTCOME), Some(&SiemField::from_str("BLOCK")));
                assert_eq!(log.field(field_dictionary::HTTP_RESPONSE_STATUS_CODE), Some(&SiemField::U64(503)));
                assert_eq!(log.field(field_dictionary::URL_DOMAIN), Some(&SiemField::from_str("pornpage.com")));
                assert_eq!(log.field(field_dictionary::DESTINATION_PORT), Some(&SiemField::U64(443)));
                assert_eq!(log.field(field_dictionary::DESTINATION_BYTES), Some(&SiemField::U64(0)));
                assert_eq!(chrono::NaiveDateTime::from_timestamp(log.event_created()/1000,0).to_string(),"2021-02-14 00:02:33");
                assert_eq!(log.field(field_dictionary::RULE_CATEGORY), Some(&SiemField::from_str("Pornography")));
            },
            Err(_) => {
                panic!("Cannot parse log")
            }
        }
    }

    
}