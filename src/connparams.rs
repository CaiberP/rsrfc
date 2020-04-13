use widestring::*;

use crate::rfc::*;

/// Simple structure that supplies arbitrary key,value
/// pairs to the SAP RFC library
pub struct RfcConnParmHelper {
    parms: Vec<(Vec<u16>, Vec<u16>)>,
}

impl RfcConnParmHelper {
    /// Create an empty new structure
    pub fn new() -> RfcConnParmHelper {
        RfcConnParmHelper { parms: Vec::new() }
    }

    /// Add a key,value pair
    pub fn add(&mut self, k: &str, v: &str) {
        let k_c = U16CString::from_str(k).unwrap().into_vec_with_nul();
        let v_c = U16CString::from_str(v).unwrap().into_vec_with_nul();
        self.parms.push((k_c, v_c));
    }

    pub fn as_vec<F, T>(&self, mut f: F) -> T
    where
        F: FnMut(Vec<RfcConnectionParameter>) -> T,
    {
        let pp = self
            .parms
            .iter()
            .map(|(k, v)| RfcConnectionParameter {
                name: k.as_ptr(),
                value: v.as_ptr(),
            })
            .collect();
        f(pp)
    }
}
