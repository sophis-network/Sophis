use crate::error::Error;
use crate::result::Result;
use sophis_consensus_core::constants::SOMPI_PER_SOPHIS;
use std::fmt::Display;

pub fn try_parse_required_nonzero_sophis_as_sompi_u64<S: ToString + Display>(sophis_amount: Option<S>) -> Result<u64> {
    if let Some(sophis_amount) = sophis_amount {
        let sompi_amount = sophis_amount
            .to_string()
            .parse::<f64>()
            .map_err(|_| Error::custom(format!("Supplied Sophis amount is not valid: '{sophis_amount}'")))?
            * SOMPI_PER_SOPHIS as f64;
        if sompi_amount < 0.0 {
            Err(Error::custom("Supplied Sophis amount is not valid: '{sophis_amount}'"))
        } else {
            let sompi_amount = sompi_amount as u64;
            if sompi_amount == 0 {
                Err(Error::custom("Supplied required sophis amount must not be a zero: '{sophis_amount}'"))
            } else {
                Ok(sompi_amount)
            }
        }
    } else {
        Err(Error::custom("Missing Sophis amount"))
    }
}

pub fn try_parse_required_sophis_as_sompi_u64<S: ToString + Display>(sophis_amount: Option<S>) -> Result<u64> {
    if let Some(sophis_amount) = sophis_amount {
        let sompi_amount = sophis_amount
            .to_string()
            .parse::<f64>()
            .map_err(|_| Error::custom(format!("Supplied Sophis amount is not valid: '{sophis_amount}'")))?
            * SOMPI_PER_SOPHIS as f64;
        if sompi_amount < 0.0 {
            Err(Error::custom("Supplied Sophis amount is not valid: '{sophis_amount}'"))
        } else {
            Ok(sompi_amount as u64)
        }
    } else {
        Err(Error::custom("Missing Sophis amount"))
    }
}

pub fn try_parse_optional_sophis_as_sompi_i64<S: ToString + Display>(sophis_amount: Option<S>) -> Result<Option<i64>> {
    if let Some(sophis_amount) = sophis_amount {
        let sompi_amount = sophis_amount
            .to_string()
            .parse::<f64>()
            .map_err(|_e| Error::custom(format!("Supplied Sophis amount is not valid: '{sophis_amount}'")))?
            * SOMPI_PER_SOPHIS as f64;
        if sompi_amount < 0.0 {
            Err(Error::custom("Supplied Sophis amount is not valid: '{sophis_amount}'"))
        } else {
            Ok(Some(sompi_amount as i64))
        }
    } else {
        Ok(None)
    }
}
