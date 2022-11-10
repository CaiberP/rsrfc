extern crate dlopen;
#[macro_use]
extern crate dlopen_derive;
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

pub enum RfcValue {
    RfcString(String),
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
pub struct RfcConnection<'rfclib> {
    connection_handle: *mut RfcConnectionHandle,
    rfc_lib: &'rfclib RfcLib
}

/// An RFC function
pub struct RfcFunction<'conn, 'fun: 'conn> {
    connection: &'conn RfcConnection<'conn>,
    fun: *mut RfcDataContainerHandle,
    fun_desc: Vec<RfcParameter<'conn, 'fun>>,
}

    /// Open a conneciton to an SAP system via RFC.
    /// If you need to specify more RFC connection parameters than
    /// RfcConnectinoParameters would allow you, use from_parm_helper or from_hashmap
    /// methods instead.
pub struct RfcLib {
    rfc_api: dlopen::wrapper::Container<crate::rfc::RfcApi>
}


impl RfcLib {
    #[cfg(all(target_family = "unix", not(target_vendor = "apple")))]
    pub fn new() -> Result<RfcLib, String> {
        let rfc_api : dlopen::wrapper::Container<crate::rfc::RfcApi> = unsafe {
            dlopen::wrapper::Container::load("libsapnwrfc.so")
        }.map_err(|e| {
            format!("Error trying to load libsapnwrfc: {:?}", e)
        })?;
        Ok(RfcLib {
            rfc_api
        })
    }

    #[cfg(all(target_family = "unix", target_vendor = "apple"))]
    pub fn new() -> Result<RfcLib, String> {
        let rfc_api : dlopen::wrapper::Container<crate::rfc::RfcApi> = unsafe {
            dlopen::wrapper::Container::load("libsapnwrfc.dylib")
        }.map_err(|e| {
            format!("Error trying to load libsapnwrfc: {:?}", e)
        })?;
        Ok(RfcLib {
            rfc_api
        })
    }

    #[cfg(target_family = "windows")]
    pub fn new() -> Result<RfcLib, String> {
        let rfc_api : dlopen::wrapper::Container<crate::rfc::RfcApi> = unsafe {
            dlopen::wrapper::Container::load("sapnwrfc.dll")
        }.map_err(|e| {
            format!("Error trying to load libsapnwrfc: {:?}", e)
        })?;
        Ok(RfcLib {
            rfc_api
        })
    }
}

impl <'rfclib>RfcConnection<'rfclib> {
    pub fn new<'conn>(conn_info: &RfcConnectionParameters, rfc_lib: &'conn RfcLib) -> Result<RfcConnection<'conn>, RfcErrorInfo> {
        let parms = conn_info.convert();
        RfcConnection::from_parm_helper(parms, rfc_lib)
    }

    /// Open a connection to an SAP system via RFC
    pub fn from_parm_helper<'conn>(parms: RfcConnParmHelper, rfc_lib: &'conn RfcLib) -> Result<RfcConnection<'conn>, RfcErrorInfo> {
        let mut err_trunk = RfcErrorInfo::new();
        unsafe {
            let ch =
                parms.as_vec(|pv| rfc_lib.rfc_api.RfcOpenConnection(pv.as_ptr(), pv.len() as u32, &mut err_trunk));
            if ch.is_null() {
                Err(err_trunk)
            } else {
                Ok(RfcConnection {
                    connection_handle: ch,
                    rfc_lib
                })
            }
        }
    }

    /// Open a connection to an SAP system via RFC
    pub fn from_hashmap<'conn>(parms: &HashMap<String, String>, rfc_lib: &'conn RfcLib) -> Result<RfcConnection<'conn>, RfcErrorInfo> {
        let mut ph = RfcConnParmHelper::new();
        for (k, v) in parms {
            ph.add(k, v);
        }
        RfcConnection::from_parm_helper(ph, rfc_lib)
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
            let fd = self.rfc_lib.rfc_api.RfcGetFunctionDesc(self.connection_handle, name_uc.as_ptr(), &mut err_trunk);
            if fd.is_null() {
                return Err(err_trunk);
            }
            let ff = self.rfc_lib.rfc_api.RfcCreateFunction(fd, &mut err_trunk);
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
            let res = self.rfc_lib.rfc_api.RfcGetParameterCount(fd, &mut parm_count, &mut err_trunk);
            if !res.is_ok() {
                return Err(err_trunk);
            }

            let mut fun_desc = Vec::new();
            {
                let mut rpd = RfcParameterDesc::new(&self.rfc_lib.rfc_api);
                fun_desc.reserve_exact(parm_count as usize);
                for i in 0..parm_count {
                    let res = self.rfc_lib.rfc_api.RfcGetParameterDescByIndex(fd, i, &mut rpd, &mut err_trunk);
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
        let res = unsafe { self.connection.rfc_lib.rfc_api.RfcInvoke(self.connection.connection_handle, self.fun, &mut err_trunk) };
        if !res.is_ok() {
            return Err(err_trunk);
        }
        Ok(())
    }
}

impl <'rfclib> Drop for RfcConnection<'rfclib> {
    fn drop(&mut self) {
        if !self.connection_handle.is_null() {
            let mut err_trunk = RfcErrorInfo::new();
            let res = unsafe { self.rfc_lib.rfc_api.RfcCloseConnection(self.connection_handle, &mut err_trunk) };
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
            let res = unsafe { self.connection.rfc_lib.rfc_api.RfcDestroyFunction(self.fun, &mut err_trunk) };
            if !res.is_ok() {
                eprintln!(
                    "Warning: Unable to destroy RFC function: {}",
                    String::from_utf16_lossy(&err_trunk.message)
                );
            }
        }
    }
}
