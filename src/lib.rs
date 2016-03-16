pub mod cas;

pub use cas::{CasClient, ServiceResponse, VerifyError, Name, TicketError};

#[cfg(test)]
mod test {
    #[test]
    fn it_works() {}
}
