extern crate url;
extern crate hyper;
extern crate xml;

use self::url::{Url, ParseError};
use self::hyper::server::response::Response;
use self::hyper::status::StatusCode;
use self::hyper::header::Location;
use self::hyper::Client;
use self::hyper::error::Error as HyperError;
use self::xml::reader::{EventReader, XmlEvent};
use self::xml::reader::Error as XmlError;

pub type Name = String;
pub type TicketError = String;

pub struct CasServer {
    login_url: Url,
    logout_url: Url,
    verify_url: Url,
    service_url: Url,
}

pub enum ServiceResponse {
    Success(Name),
    Failure(TicketError),
}

enum XmlMatchStatus {
    None,
    ExpectSuccess,
}

pub enum VerifyError {
    Hyper(HyperError),
    Xml(XmlError),
}

impl From<HyperError> for VerifyError {
    fn from(err: HyperError) -> VerifyError {
        VerifyError::Hyper(err)
    }
}
impl From<XmlError> for VerifyError {
    fn from(err: XmlError) -> VerifyError {
        VerifyError::Xml(err)
    }
}

impl CasServer {
    pub fn new(
        base_url: &str, login_path: &str, logout_path: &str, verify_path: &str,
        service_url: &str) -> Result<CasServer, ParseError> {
        Ok(CasServer {
            login_url: try!(
                Url::parse(&format!("{}{}", base_url, login_path))),
            logout_url: try!(
                Url::parse(&format!("{}{}", base_url, logout_path))),
            verify_url: try!(
                Url::parse(&format!("{}{}", base_url, verify_path))),
            service_url: try!(Url::parse(service_url)),
        })
    }

    pub fn login_redirect(&self, mut res: Response) {
        let mut url = self.login_url.clone();
        let param = vec![("service", self.service_url.serialize())];
        url.set_query_from_pairs(param);
        {
            let mut s = res.status_mut();
            *s = StatusCode::Found;
        }
        {
            let mut h = res.headers_mut();
            h.set::<Location>(Location(url.serialize()));
        }
        res.send(b"").unwrap();
    }

    pub fn logout_redirect(&self, mut res: Response) {
        {
            let mut s = res.status_mut();
            *s = StatusCode::Found;
        }
        {
            let mut h = res.headers_mut();
            h.set::<Location>(Location(self.logout_url.serialize()));
        }
        res.send(b"").unwrap();
    }

    pub fn verify_ticket(&self, ticket: &str)
        -> Result<ServiceResponse, VerifyError> {
        let mut url: Url = self.verify_url.clone();
        let param = vec![
            ("service", self.service_url.serialize()),
            ("ticket", ticket.to_string()),
        ];
        url.set_query_from_pairs(param);

        let res = try!(Client::new().get(&url.serialize()).send());

        let parser = EventReader::new(res);
        let mut status = XmlMatchStatus::None;
        for e in parser {
            match try!(e) {
                XmlEvent::StartElement { name, attributes, .. } => {
                    if name.local_name == "authenticationSuccess".to_string() {
                        status = XmlMatchStatus::ExpectSuccess;
                    } else if name.local_name == "authenticationFailure"
                        .to_string() {
                            let reason = attributes[0].value.clone();
                            return Ok(ServiceResponse::Failure(reason));
                    }
                }
                XmlEvent::Characters(s) => {
                    match status {
                        XmlMatchStatus::None => {}
                        XmlMatchStatus::ExpectSuccess => {
                            return Ok(ServiceResponse::Success(s));
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(ServiceResponse::Success("mtb89".to_string()))
    }
}
