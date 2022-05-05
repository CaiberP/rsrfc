/// Various kinds of RFC errors
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum RfcRc {
    RfcOk,                        // /< Everything O.K. Used by every function
    RfcCommunicationFailure,      // /< Error in Network & Communication layer
    RfcLogonFailure, // /< Unable to logon to SAP system. Invalid password, user locked, etc.
    RfcAbapRuntimeFailure, // /< SAP system runtime error (SYSTEM_FAILURE): Shortdump on the backend side
    RfcAbapMessage,        // /< The called function module raised an E-, A- or X-Message
    RfcAbapException, // /< The called function module raised an Exception (RAISE or MESSAGE ... RAISING)
    RfcClosed,        // /< Connection closed by the other side
    RfcCanceled,      // /< No longer used
    RfcTimeout,       // /< Time out
    RfcMemoryInsufficient, // /< Memory insufficient
    RfcVersionMismatcH, // /< Version mismatch
    RfcInvalidProtocol, // /< The received data has an unsupported format
    RfcSerializationFailure, // /< A problem while serializing or deserializing RFM parameters
    RfcInvalidHandle, // /< An invalid handle was passed to an API call
    RfcRetry, // /< RfcListenAndDispatch did not receive an Rfc request during the timeout period
    RfcExternalFailure, // /< Error in external custom code. (E.g. in the function handlers or tRfc handlers.) Results in SYSTEM_FAILURE
    RfcExecuted, // /< Inbound tRfc Call already executed (needs to be returned from RfcON_CHECK_TRANSACTION in case the TID is already known and successfully processed before.)
    RfcNotFound, // /< Function or structure definition not found (Metadata API)
    RfcNotSupported, // /< The operation is not supported on that handle
    RfcIllegalState, // /< The operation is not supported on that handle at the current point of time (e.g. trying a callback on a server handle, while not in a call)
    RfcInvalidParameter, // /< An invalid parameter was passed to an API call, (e.g. invalid name, type or length)
    RfcCodepageConversionFailure, // /< Codepage conversion error
    RfcConversionFailure, // /< Error while converting a parameter to the correct data type
    RfcBufferTooSmall, // /< The given buffer was to small to hold the entire parameter. Data has been truncated.
    RfcTableMoveBof,   // /< Trying to move the current position before the first row of the table
    RfcTableMoveEof,   // /< Trying to move the current position after the last row of the table
    RfcStartSapguiFailure, // /< Failed to start and attach SAPGUI to the Rfc connection
    RfcAbapClassException, // /< The called function module raised a class based exception
    RfcUnknownError,   // /< "Something" went wrong, but I don't know what...
    RfcAuthorizationFailure, // /< Authorization check error

    RfcCaiberp = 65536, // CaiberP custom error
}

impl RfcRc {
    /// Return true if the result was RfcOk (no error)
    pub fn is_ok(&self) -> bool {
        self == &RfcRc::RfcOk
    }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum RfcErrorGroup {
    Ok,
    AbapApplicationFailure,
    AbapRuntimeFailure,
    LogonFailure,
    CommunicationFailure,
    ExternalRuntimeFailure,
    ExternalApplicationFailure,
    ExternalAuthorizationFailure,

    CaiberP = 65536, // Custom error
}

#[repr(C)]
pub struct RfcErrorInfo {
    pub code: RfcRc,
    pub group: RfcErrorGroup,
    pub key: [u16; 128],
    pub message: [u16; 512],
    pub abap_msg_class: [u16; 21],
    pub abap_msg_type: [u16; 2],
    pub abap_msg_number: [u16; 4],
    pub abap_msg_v1: [u16; 51],
    pub abap_msg_v2: [u16; 51],
    pub abap_msg_v3: [u16; 51],
    pub abap_msg_v4: [u16; 51],
}

impl std::fmt::Debug for RfcErrorInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut len = 0;
        for i in 0..self.message.len() {
            if *self.message.get(i).unwrap() == 0 {
                len = i;
                break;
            }
        }
        let mut msg = String::from_utf16_lossy(&self.message);
        msg.truncate(len);
        write!(f, "{}", msg)
    }
}

impl std::fmt::Display for RfcErrorInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut len = 0;
        for i in 0..self.message.len() {
            if *self.message.get(i).unwrap() == 0 {
                len = i;
                break;
            }
        }
        let mut msg = String::from_utf16_lossy(&self.message);
        msg.truncate(len);
        write!(f, "{}", msg)
    }
}

impl std::error::Error for RfcErrorInfo {}
