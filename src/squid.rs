use std::borrow::Cow;
use usiem::components::common::LogParsingError;
use usiem::events::common::{HttpMethod, WebProtocol};
use usiem::events::field::{SiemField, SiemIp};
use usiem::events::field_dictionary;
use usiem::events::webproxy::{WebProxyEvent, WebProxyOutcome};
use usiem::events::{SiemEvent, SiemLog};

pub fn parse_log(log: SiemLog) -> Result<SiemLog, LogParsingError> {
    let log_line = log.message();

    let log_start_pos = if log_line.starts_with("<") {
        let squid_pos = match log_line.find("squid") {
            Some(pos) => pos,
            None => return Err(LogParsingError::NoValidParser(log)),
        };

        match log_line[squid_pos..].find(": ") {
            Some(pos) => squid_pos + pos + 2,
            None => return Err(LogParsingError::ParserError(log)),
        }
    } else {
        0
    };

    let log_content = &log_line[log_start_pos..];
    let mut log_parsed = [""; 10];
    let mut last_pos = 0;
    let mut array_pos = 0;
    for (pos, c) in log_content.char_indices() {
        if c == ' ' {
            if (last_pos + 1) <= pos {
                log_parsed[array_pos] = &log_content[last_pos..pos];
                array_pos += 1;
            }
            last_pos = pos + 1;
        }
    }
    log_parsed[array_pos] = &log_content[last_pos..];
    let event_created = log_parsed[0];
    let event_created = match event_created.parse::<f64>() {
        Ok(num) => num as i64,
        Err(_) => return Err(LogParsingError::ParserError(log)),
    };
    
    let source_ip = match SiemIp::from_ip_str(log_parsed[2]) {
        Ok(ip) => ip,
        Err(_) => return Err(LogParsingError::NoValidParser(log)),
    };
    let (_connection_class, destination_ip) = match destination_ip_from_squid(log_parsed[8]) {
        Ok((cls, ip)) => {
            if ip == "-" {
                (cls, SiemIp::V4(0))
            }else{
                match SiemIp::from_ip_str(ip) {
                    Ok(v) => (cls, v),
                    Err(_) => return Err(LogParsingError::ParserError(log)),
                }
            }
        },
        Err(_) => return Err(LogParsingError::ParserError(log)),
    };
    

    let url_parsed = log_parsed[6];
    let (protocol, domain, url, destination_port) = match parse_url(url_parsed) {
        Ok(data) => data,
        Err(_) => return Err(LogParsingError::ParserError(log)),
    };
    let domain = if ["http","https","ftp","ws","wss"].contains(&domain) {
        ""
    }else{
        domain
    };
    let user_name = match log_parsed[7] {
        "-" => Cow::Borrowed(""),
        usr => Cow::Owned(usr.to_string()),
    };
    let (squid_code, http_code) = match parse_squid_code(log_parsed[3]) {
        Ok(data) => data,
        Err(_) => return Err(LogParsingError::ParserError(log)),
    };
    //let mut fields : BTreeMap<&'static str, std::string::String> = BTreeMap::new();
    //fields.insert(SQUID_CONNECTION_DURATION, (log_parsed[1]).to_owned());
    //fields.insert(SQUID_CODE, squid_code);
    let in_bytes = match (log_parsed[4]).parse::<u32>() {
        Ok(v) => v,
        Err(_) => return Err(LogParsingError::ParserError(log)),
    };
    let httpmethod = http_method(log_parsed[5]);
    let mime_type = Cow::Owned(log_parsed[9].to_string());
    let mut log = SiemLog::new(
        (&log_line[log_start_pos..]).to_string(),
        log.event_received(),
        log.origin().clone(),
    );

    log.set_event_created(event_created);
    log.set_event(SiemEvent::WebProxy(WebProxyEvent {
        source_ip,
        destination_ip,
        destination_port,
        domain: Cow::Owned(domain.to_string()),
        url: Cow::Owned(url.to_string()),
        http_method: httpmethod,
        http_code,
        mime_type,
        in_bytes,
        out_bytes: 0,
        protocol: parse_protocol(protocol),
        rule_name: None,
        rule_category: None,
        user_name,
        outcome: parse_outcome(squid_code,http_code),
    }));
    match log_parsed[1].parse::<u64>() {
        Ok(v) => {
            log.add_field(field_dictionary::NETWORK_DURATION, SiemField::U64(v));
        }
        Err(_) => {}
    }

    return Ok(log);
}

pub fn parse_outcome(text: &str, http_code : u32) -> WebProxyOutcome {
    if http_code >= 300 || http_code < 200{
        return WebProxyOutcome::BLOCK
    }
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

pub fn parse_squid_code<'a>(text: &'a str) -> Result<(&'a str, u32), &'static str> {
    let slash_pos = match text.find("/") {
        Some(p) => p,
        None => return Err("Invalid squid code"),
    };
    let code = match (&text[slash_pos + 1..]).parse::<u32>() {
        Ok(c) => c,
        Err(_) => return Err("Invalid squid code"),
    };
    return Ok(((&text[0..slash_pos]), code));
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
        let log = "1613260836.628    287 172.17.0.1 TCP_TUNNEL_ABORTED/200 18353 CONNECT www.google.com:443 - HIER_DIRECT/142.250.184.4 -";
        let log = SiemLog::new(log.to_string(), 0, SiemIp::V4(0));
        match super::parse_log(log) {
            Ok(log) => {
                assert_eq!(log.field(field_dictionary::SOURCE_IP), Some(&SiemField::IP(SiemIp::from_ip_str("172.17.0.1").expect("Must work"))));
                assert_eq!(log.field(field_dictionary::DESTINATION_IP), Some(&SiemField::IP(SiemIp::from_ip_str("142.250.184.4").expect("Must work"))));
                assert_eq!(log.field(field_dictionary::EVENT_OUTCOME), Some(&SiemField::from_str("ALLOW")));
                assert_eq!(log.field(field_dictionary::HTTP_RESPONSE_STATUS_CODE), Some(&SiemField::U64(200)));
                assert_eq!(log.field(field_dictionary::URL_DOMAIN), Some(&SiemField::from_str("www.google.com")));
                assert_eq!(log.field(field_dictionary::DESTINATION_PORT), Some(&SiemField::U64(443)));
                assert_eq!(log.field(field_dictionary::DESTINATION_BYTES), Some(&SiemField::U64(18353)));
                assert_eq!(chrono::NaiveDateTime::from_timestamp(log.event_created(),0).to_string(),"2021-02-14 00:00:36");
            },
            Err(_) => {
                panic!("Cannot parse log")
            }
        }
    }

    #[test]
    fn test_log_from_file_none() {
        let log = "1613260847.813      0 172.17.0.1 NONE/503 0 CONNECT https:443 - HIER_NONE/- -";
        let log = SiemLog::new(log.to_string(), 0, SiemIp::V4(0));
        match super::parse_log(log) {
            Ok(log) => {
                assert_eq!(log.field(field_dictionary::SOURCE_IP), Some(&SiemField::IP(SiemIp::from_ip_str("172.17.0.1").expect("Must work"))));
                assert_eq!(log.field(field_dictionary::DESTINATION_IP), Some(&SiemField::IP(SiemIp::from_ip_str("0.0.0.0").expect("Must work"))));
                assert_eq!(log.field(field_dictionary::EVENT_OUTCOME), Some(&SiemField::from_str("BLOCK")));
                assert_eq!(log.field(field_dictionary::HTTP_RESPONSE_STATUS_CODE), Some(&SiemField::U64(503)));
                assert_eq!(log.field(field_dictionary::URL_DOMAIN), Some(&SiemField::from_str("")));
                assert_eq!(log.field(field_dictionary::DESTINATION_PORT), Some(&SiemField::U64(443)));
                assert_eq!(log.field(field_dictionary::DESTINATION_BYTES), Some(&SiemField::U64(0)));
                assert_eq!(chrono::NaiveDateTime::from_timestamp(log.event_created(),0).to_string(),"2021-02-14 00:00:47");
            },
            Err(_) => {
                panic!("Cannot parse log")
            }
        }
    }


    #[test]
    fn test_log_from_syslog() {
        let log = "<1>1 2020-09-25T16:23:25+02:00 OPNsense.localdomain (squid-1)[91300]: 1601051005.952  18459 192.168.4.100 TCP_TUNNEL/200 7323 CONNECT ap.lijit.com:443 - HIER_DIRECT/72.251.249.9 -";
        let log = SiemLog::new(log.to_string(), 0, SiemIp::V4(0));
        match super::parse_log(log) {
            Ok(log) => {
                assert_eq!(log.field(field_dictionary::SOURCE_IP), Some(&SiemField::IP(SiemIp::from_ip_str("192.168.4.100").expect("Must work"))));
                assert_eq!(log.field(field_dictionary::DESTINATION_IP), Some(&SiemField::IP(SiemIp::from_ip_str("72.251.249.9").expect("Must work"))));
                assert_eq!(log.field(field_dictionary::EVENT_OUTCOME), Some(&SiemField::from_str("ALLOW")));
                assert_eq!(log.field(field_dictionary::HTTP_RESPONSE_STATUS_CODE), Some(&SiemField::U64(200)));
                assert_eq!(log.field(field_dictionary::URL_DOMAIN), Some(&SiemField::from_str("ap.lijit.com")));
                assert_eq!(log.field(field_dictionary::DESTINATION_PORT), Some(&SiemField::U64(443)));
                assert_eq!(log.field(field_dictionary::DESTINATION_BYTES), Some(&SiemField::U64(7323)));
                assert_eq!(chrono::NaiveDateTime::from_timestamp(log.event_created(),0).to_string(),"2020-09-25 16:23:25");
            },
            Err(_) => {
                panic!("Cannot parse log")
            }
        }
    }
    
}