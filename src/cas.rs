extern crate url;
extern crate hyper;
extern crate xml;

use self::url::{Url, ParseError};
use self::hyper::server::response::Response;
use self::hyper::server::request::Request;
use self::hyper::status::StatusCode;
use self::hyper::header::Location;
use self::hyper::Client;
use self::hyper::error::Error as HyperError;
use self::hyper::uri::RequestUri;
use self::xml::reader::{EventReader, XmlEvent, Error as XmlError};

/// The username returned by `verify_ticket` on success
pub type Name = String;
/// The error returned by `verify_ticket` on failure
pub type TicketError = String;

/// The details of a CAS server.  All URLs are the full urls
#[derive(Debug)]
pub struct CasClient {
    /// Login url (such as https://login.case.edu/cas/login)
    login_url: Url,
    /// Logout url (such as https://login.case.edu/cas/logout)
    logout_url: Url,
    /// Verify url, accessed by the server
    /// (such as https://login.case.edu/cas/serviceValidate)
    verify_url: Url,
    /// The URL of your service, which is used in the login sequence and
    /// so the login server knows where to redirect you back to
    service_url: Url,
}

/// The response from the server from `verify_ticket`
#[derive(Debug)]
pub enum ServiceResponse {
    /// Returned on successful login
    Success(Name),
    /// Returned on unsuccessful login
    Failure(TicketError),
}

#[derive(Debug)]
enum XmlMatchStatus {
    None,
    ExpectSuccess,
}

/// Errors that can happen when verifying.  Xml is unlikely.
#[derive(Debug)]
pub enum VerifyError {
    Hyper(HyperError),
    Xml(XmlError),
    Url(ParseError),
    UnsupportedUriType,
    NoTicketFound,
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
impl From<ParseError> for VerifyError {
    fn from(err: ParseError) -> VerifyError {
        VerifyError::Url(err)
    }
}

impl CasClient {
    /// Construct a new CasClient. The for each url except service_url, the
    /// \<thing\>_path is concatinated onto base_url to form the Url
    pub fn new(base_url: &str,
               login_path: &str,
               logout_path: &str,
               verify_path: &str,
               service_url: &str)
               -> Result<CasClient, ParseError> {
        Ok(CasClient {
            login_url: try!(Url::parse(&format!("{}{}", base_url, login_path))),
            logout_url: try!(Url::parse(&format!("{}{}", base_url, logout_path))),
            verify_url: try!(Url::parse(&format!("{}{}", base_url, verify_path))),
            service_url: try!(Url::parse(service_url)),
        })
    }

    /// Get the URL to redirect to for login.  Use this if you are not using
    /// Hyper as your web server
    pub fn get_login_url(&self) -> String {
        let mut url = self.login_url.clone();
        let param = vec![("service", self.service_url.serialize())];
        url.set_query_from_pairs(param);
        url.serialize()
    }

    /// Consumes a hyper::server::response::Response to return a 302 redirect
    /// to the CAS login url.  Use this if you're using Hyper as you web
    /// server
    pub fn login_redirect(&self, mut res: Response) {
        *res.status_mut() = StatusCode::Found;
        res.headers_mut().set::<Location>(Location(self.get_login_url()));
        res.send(b"").unwrap();
    }

    /// Get the URL to redirect to for logout.  Use this if you are not using
    /// Hyper as your web server
    pub fn get_logout_url(&self) -> String {
        self.logout_url.serialize()
    }

    /// Consumes a hyper::server::response::Response to return a 302 redirect
    /// to the CAS logout url.  use this if you're using Hyper as your web
    /// server
    pub fn logout_redirect(&self, mut res: Response) {
        *res.status_mut() = StatusCode::Found;
        res.headers_mut().set::<Location>(Location(self.get_logout_url()));
        res.send(b"").unwrap();
    }

    /// When login completes, the CAS server will redirec to your service_url
    /// with the added parameter ticket=\<ticket\>.  You pass \<ticket\> here,
    /// and it checks with the CAS server whether or not the login was
    /// successful.  On success, this will return
    /// `Ok(ServiceResponse::Success(username))`, where username is the username
    /// from the CAS server.  On failure it returns
    /// `Ok(ServiceResponse::Failure(reason))`, where reason is the reason for
    /// the failure.  In the event of an http error or an xml error, this
    /// returns Err(VerifyError)
    pub fn verify_ticket(&self, ticket: &str) -> Result<ServiceResponse, VerifyError> {
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
                    if name.local_name == "authenticationSuccess" {
                        status = XmlMatchStatus::ExpectSuccess;
                    } else if name.local_name == "authenticationFailure" {
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

        let error = "did not detect authentication reply from CAS server".to_owned();
        Ok(ServiceResponse::Failure(error))
    }

    /// Takes a reference to a request, and verifies the ticket in that request.
    /// Will return an `Err(VerifyError::NoTicketFound)` if it can't find the
    /// ticket in the url query
    pub fn verify_from_request(&self, request: &Request) -> Result<ServiceResponse, VerifyError> {
        let url = match request.uri.clone() {
            RequestUri::AbsolutePath(s) => try!(Url::parse(&format!("http://none{}", s))),
            RequestUri::AbsoluteUri(u) => u,
            _ => return Err(VerifyError::UnsupportedUriType),
        };
        let queries = try!(url.query_pairs().ok_or(VerifyError::NoTicketFound));

        let mut ticket = "".to_owned();
        // TODO: There's got to be a better way to do this?
        for i in queries {
            let (v, t) = i;
            if v == "ticket" {
                ticket = t;
            }
        }
        if ticket == "" {
            return Err(VerifyError::NoTicketFound);
        }

        self.verify_ticket(&ticket)
    }
}
