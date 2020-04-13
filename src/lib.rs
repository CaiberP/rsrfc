extern crate widestring;

use std::collections::HashMap;
use widestring::*;

pub mod connparams;
pub mod error;
mod rfc;

use crate::connparams::*;
use crate::error::*;
use crate::rfc::*;

/// Simple RFC connections require only a few parameters.
/// You can use this struct to supply them.
pub struct RfcConnectionParameters<'a> {
    pub ashost: &'a str,
    pub sysnr: &'a str,
    pub client: &'a str,
    pub user: &'a str,
    pub passwd: &'a str,
    pub lang: &'a str,
}

impl<'a> RfcConnectionParameters<'a> {
    /// Convert to a more generic RfcConnParmHelper structure
    fn convert(&self) -> RfcConnParmHelper {
        let mut parms = RfcConnParmHelper::new();
        parms.add("ashost", &self.ashost);
        parms.add("sysnr", &self.sysnr);
        parms.add("client", &self.client);
        parms.add("user", &self.user);
        parms.add("passwd", &self.passwd);
        parms.add("lang", &self.lang);
        parms
    }
}

/// An open RFC connection
pub struct RfcConnection {
    connection_handle: *mut RfcConnectionHandle,
}

/// An RFC function
pub struct RfcFunction<'conn, 'fun: 'conn> {
    connection: &'conn RfcConnection,
    fun: *mut RfcDataContainerHandle,
    fun_desc: Vec<RfcParameter<'conn, 'fun>>,
}

impl RfcConnection {
    /// Open a conneciton to an SAP system via RFC.
    /// If you need to specify more RFC connection parameters than
    /// RfcConnectinoParameters would allow you, use from_parm_helper or from_hashmap
    /// methods instead.
    pub fn new(conn_info: &RfcConnectionParameters) -> Result<RfcConnection, RfcErrorInfo> {
        let parms = conn_info.convert();
        RfcConnection::from_parm_helper(parms)
    }

    /// Open a connection to an SAP system via RFC
    pub fn from_parm_helper(parms: RfcConnParmHelper) -> Result<RfcConnection, RfcErrorInfo> {
        let mut err_trunk = RfcErrorInfo::new();
        unsafe {
            let ch =
                parms.as_vec(|pv| RfcOpenConnection(pv.as_ptr(), pv.len() as u32, &mut err_trunk));
            if ch.is_null() {
                Err(err_trunk)
            } else {
                Ok(RfcConnection {
                    connection_handle: ch,
                })
            }
        }
    }

    /// Open a connection to an SAP system via RFC
    pub fn from_hashmap(parms: &HashMap<String, String>) -> Result<RfcConnection, RfcErrorInfo> {
        let mut ph = RfcConnParmHelper::new();
        for (k, v) in parms {
            ph.add(k, v);
        }
        RfcConnection::from_parm_helper(ph)
    }

    /// Return a reference to an RFC enabled function, if it exists on
    /// the remote system.
    pub fn get_function<'conn, 'fun: 'conn>(
        &'conn self,
        name: &str,
    ) -> Result<RfcFunction<'conn, 'fun>, RfcErrorInfo> {
        let name_uc = U16CString::from_str(name).unwrap().into_vec_with_nul();
        let mut err_trunk = RfcErrorInfo::new();
        unsafe {
            let fd = RfcGetFunctionDesc(self.connection_handle, name_uc.as_ptr(), &mut err_trunk);
            if fd.is_null() {
                return Err(err_trunk);
            }
            let ff = RfcCreateFunction(fd, &mut err_trunk);
            if ff.is_null() {
                return Err(err_trunk);
            }
            /*
            let fftd = unsafe { RfcDescribeType(ff, &mut err_trunk) };
            if fftd.is_null() {
                return Err(err_trunk);
            }
            let fun_desc = RfcDecodedFieldDesc::from_handle(fftd)?;
            */
            let mut parm_count: u32 = 0;
            let res = RfcGetParameterCount(fd, &mut parm_count, &mut err_trunk);
            if !res.is_ok() {
                return Err(err_trunk);
            }

            let mut fun_desc = Vec::new();
            {
                let mut rpd = RfcParameterDesc::new();
                fun_desc.reserve_exact(parm_count as usize);
                for i in 0..parm_count {
                    let res = RfcGetParameterDescByIndex(fd, i, &mut rpd, &mut err_trunk);
                    if !res.is_ok() {
                        return Err(err_trunk);
                    }
                    let parm = rpd.to_parameter(i, ff)?;
                    fun_desc.push(parm);
                }
            }

            Ok(RfcFunction {
                connection: self,
                fun: ff,
                fun_desc,
            })
        }
    }
}

impl<'conn, 'fun> RfcFunction<'conn, 'fun> {
    /// Get a reference to an RFC parameter using the parameter index.
    pub fn get_parameter_by_index(
        &self,
        index: usize,
    ) -> Option<&RfcParameter<'conn, 'fun>> {
        self.fun_desc.get(index)
    }

    /// Get a mutable reference to an RFC parameter by using the parameter index.
    pub fn get_parameter_by_index_mut(
        &mut self,
        index: usize,
    ) -> Option<&mut RfcParameter<'conn, 'fun>> {
        self.fun_desc.get_mut(index)
    }

    /// Get a mutable reference to an RFC parameter using the parameter name. This
    /// is a case insensitive operation.
    pub fn get_mut_parameter(
        &mut self,
        parameter_name: &str,
    ) -> Option<&mut RfcParameter<'conn, 'fun>> {
        for p in self.fun_desc.iter_mut() {
            if p.name.eq_ignore_ascii_case(parameter_name) {
                return Some(p);
            }
        }
        None
    }

    /// Get a reference to an RFC parameter using the parameter name. This
    /// is a case insensitive operation.
    pub fn get_parameter(&self, parameter_name: &str) -> Option<&RfcParameter<'conn, 'fun>> {
        for p in self.fun_desc.iter() {
            if p.name.eq_ignore_ascii_case(parameter_name) {
                return Some(p);
            }
        }
        None
    }

    /// Call the remote function
    pub fn call(&mut self) -> Result<(), RfcErrorInfo> {
        let mut err_trunk = RfcErrorInfo::new();
        let res = unsafe { RfcInvoke(self.connection.connection_handle, self.fun, &mut err_trunk) };
        if !res.is_ok() {
            return Err(err_trunk);
        }
        Ok(())
    }
}

impl Drop for RfcConnection {
    fn drop(&mut self) {
        if !self.connection_handle.is_null() {
            let mut err_trunk = RfcErrorInfo::new();
            let res = unsafe { RfcCloseConnection(self.connection_handle, &mut err_trunk) };
            if !res.is_ok() {
                eprintln!(
                    "Warning: Unable to close RFC connection: {}",
                    String::from_utf16_lossy(&err_trunk.message)
                );
            }
        }
    }
}

impl<'conn, 'fun> Drop for RfcFunction<'conn, 'fun> {
    fn drop(&mut self) {
        if !self.fun.is_null() {
            let mut err_trunk = RfcErrorInfo::new();
            let res = unsafe { RfcDestroyFunction(self.fun, &mut err_trunk) };
            if !res.is_ok() {
                eprintln!(
                    "Warning: Unable to destroy RFC function: {}",
                    String::from_utf16_lossy(&err_trunk.message)
                );
            }
        }
    }
}
