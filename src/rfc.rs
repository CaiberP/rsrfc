use std::marker::PhantomData;
use std::ptr::null_mut;

use std::cmp::min;
use widestring::U16CString;

use crate::error::*;

pub enum RfcFunctionDescHandle {}
pub enum RfcConnectionHandle {}
pub enum RfcDataContainerHandle {}
pub enum RfcExtendedDescription {}

/// Parameters specifying the RFC connection details
#[repr(C)]
pub struct RfcConnectionParameter {
    pub name: *const u16,
    pub value: *const u16,
}

/// RFC data type
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum RfcType {
    Char = 0,
    Date = 1,
    Bcd = 2,
    Time = 3,
    Byte = 4,
    Table = 5,
    Num = 6,
    Float = 7,
    Int = 8,
    Int2 = 9,
    Int1 = 10,
    Null = 14,
    AbapObject = 16,
    Structure = 17,
    Decf16 = 23,
    Decf34 = 24,
    XmlData = 28,
    String = 29,
    XString = 30,
    Int8 = 31,
    UtcLong = 32,
    UtcSecond = 33,
    UtcMinute = 34,
    DtDay = 35,
    DtMonth = 36,
    TSecond = 37,
    TMinute = 38,
    CDay = 39,
    Box = 40,
    GenericBox = 41,
}

impl RfcType {
    /// Return true if the RFC type is a table or a struct.
    /// (A table is a list of structs, if you will)
    pub fn is_struct_or_table(&self) -> bool {
        if self == &RfcType::Structure {
            return true;
        }
        if self == &RfcType::Table {
            return true;
        }
        false
    }

    /// Return true if the RFC type is a table.
    pub fn is_table(&self) -> bool {
        self == &RfcType::Table
    }

    /// Raise an error if the RFC type is neither a struct nor a table
    pub fn ensure_struct_or_table(&self) -> Result<(), RfcErrorInfo> {
        if self.is_struct_or_table() {
            Ok(())
        } else {
            Err(RfcErrorInfo::custom("Expected struct table"))
        }
    }

    /// Raise an error if the RFC type is not a table
    pub fn ensure_table(&self) -> Result<(), RfcErrorInfo> {
        if self.is_table() {
            Ok(())
        } else {
            Err(RfcErrorInfo::custom("Expected table"))
        }
    }
}

/// RFC enabled functions can take different kinds of parameters.
/// This enum specified the kind.
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum RfcDirection {
    /// A parameter goes from the caller to the callee
    RfcImport = 1,
    /// A parameter goes from the callee to the caller
    RfcExport = 2,
    /// A parameter goes in both directions
    RfcChanging = 1 | 2,
    /// Tables are a special kind of parameter. They go in
    /// both directions.
    RfcTables = 1 | 2 | 4,
}

impl RfcDirection {
    /// Return true if the RFC parameter can be modified
    pub fn can_write(&self) -> bool {
        match &self {
            &RfcDirection::RfcImport => true,
            &RfcDirection::RfcExport => false,
            &RfcDirection::RfcChanging => true,
            &RfcDirection::RfcTables => true,
        }
    }

    /// Return true if the RFC parameter can be read
    pub fn can_read(&self) -> bool {
        match &self {
            &RfcDirection::RfcImport => false,
            &RfcDirection::RfcExport => true,
            &RfcDirection::RfcChanging => true,
            &RfcDirection::RfcTables => true,
        }
    }
}

/// Internal RFC lib structure describing one RFC parameter.
#[repr(C)]
pub struct RfcFieldDesc {
    name: [u16; 31],
    field_type: RfcType,
    nuc_length: u32,
    nuc_offset: u32,
    uc_length: u32,
    uc_offset: u32,
    decimals: u32,
    type_desc_handle: *mut RfcDataContainerHandle,
    extended_description: *mut RfcExtendedDescription,
}

impl RfcFieldDesc {
    /// Create an empty RFC field desciption
    pub fn new() -> RfcFieldDesc {
        RfcFieldDesc {
            name: [0 as u16; 31],
            field_type: RfcType::String,
            nuc_length: 0,
            nuc_offset: 0,
            uc_length: 0,
            uc_offset: 0,
            decimals: 0,
            type_desc_handle: null_mut(),
            extended_description: null_mut(),
        }
    }

    /// Convert to an RFC parameter
    pub fn to_parameter<'conn, 'strct: 'conn>(
        &self,
        index: u32,
        fun: *mut RfcDataContainerHandle,
    ) -> Result<RfcParameter<'conn, 'strct>, RfcErrorInfo> {
        let name_s = unsafe { U16CString::from_ptr_with_nul(self.name.as_ptr(), 31) };
        if let Err(e) = name_s {
            return Err(RfcErrorInfo::custom(&e.to_string()));
        }
        let name_s = name_s.unwrap().to_string();
        if let Err(e) = name_s {
            return Err(RfcErrorInfo::custom(&e.to_string()));
        }
        let name_s = name_s.unwrap();

        let mut structure_or_table = null_mut();
        if &self.field_type == &RfcType::Structure {
            let mut err_trunk = RfcErrorInfo::new();
            let res = unsafe {
                RfcGetStructureByIndex(fun, index, &mut structure_or_table, &mut err_trunk)
            };
            if !res.is_ok() {
                return Err(err_trunk);
            }
        } else if &self.field_type == &RfcType::Table {
            let mut err_trunk = RfcErrorInfo::new();
            let res =
                unsafe { RfcGetTableByIndex(fun, index, &mut structure_or_table, &mut err_trunk) };
            if !res.is_ok() {
                return Err(err_trunk);
            }
        }

        let struct_def = if structure_or_table.is_null() {
            None
        } else {
            let res = RfcDecodedFieldDesc::from_handle(structure_or_table)?;
            Some(res)
        };

        Ok(RfcParameter {
            index,
            name: name_s,
            field_type: self.field_type,
            direction: RfcDirection::RfcChanging,
            len: self.uc_length,
            struct_def,
            default_value: None,
            optional: false,
            fun,
            structure_or_table,
            p1: PhantomData,
            p2: PhantomData,
        })
    }
}

/// Decoded RFC field description
#[derive(Debug)]
pub struct RfcDecodedFieldDesc<'conn, 'strct: 'conn> {
    pub fields: Vec<RfcDecodedField<'conn, 'strct>>,
    pub parameters: Vec<RfcParameter<'conn, 'strct>>,
}

/// An RFC parameter description, RFC library internal structure
#[repr(C)]
pub struct RfcParameterDesc {
    pub name: [u16; 31],
    pub field_type: RfcType,
    pub direction: RfcDirection,
    pub nuc_length: u32,
    pub uc_length: u32,
    pub decimals: u32,
    pub type_desc_handle: *mut RfcDataContainerHandle,
    pub default_value: [u16; 31],
    pub parameter_text: [u16; 80],
    pub optional: u8,
    pub extended_description: *mut u8,
}

impl RfcParameterDesc {
    pub fn new() -> RfcParameterDesc {
        RfcParameterDesc {
            name: [0 as u16; 31],
            field_type: RfcType::String,
            direction: RfcDirection::RfcExport,
            nuc_length: 0,
            uc_length: 0,
            decimals: 0,
            type_desc_handle: null_mut(),
            default_value: [0 as u16; 31],
            parameter_text: [0 as u16; 80],
            optional: 0 as u8,
            extended_description: null_mut(),
        }
    }

    pub fn to_parameter<'conn, 'strct: 'conn>(
        &self,
        index: u32,
        fun: *mut RfcDataContainerHandle,
    ) -> Result<RfcParameter<'conn, 'strct>, RfcErrorInfo> {
        let name_s = unsafe { U16CString::from_ptr_with_nul(self.name.as_ptr(), 31) };
        if let Err(e) = name_s {
            return Err(RfcErrorInfo::custom(&e.to_string()));
        }
        let name_s = name_s.unwrap().to_string();
        if let Err(e) = name_s {
            return Err(RfcErrorInfo::custom(&e.to_string()));
        }
        let name_s = name_s.unwrap();

        let default_value = if self.default_value[0] == 0 {
            None
        } else {
            let default_value_s =
                unsafe { U16CString::from_ptr_with_nul(self.default_value.as_ptr(), 31) };
            if let Err(e) = default_value_s {
                return Err(RfcErrorInfo::custom(&e.to_string()));
            }
            let default_value_s = default_value_s.unwrap().to_string();
            if let Err(e) = default_value_s {
                return Err(RfcErrorInfo::custom(&e.to_string()));
            }
            Some(default_value_s.unwrap())
        };

        let mut structure_or_table = null_mut();
        if &self.field_type == &RfcType::Structure {
            let mut err_trunk = RfcErrorInfo::new();
            let res = unsafe {
                RfcGetStructureByIndex(fun, index, &mut structure_or_table, &mut err_trunk)
            };
            if !res.is_ok() {
                return Err(err_trunk);
            }
        } else if &self.field_type == &RfcType::Table {
            let mut err_trunk = RfcErrorInfo::new();
            let res =
                unsafe { RfcGetTableByIndex(fun, index, &mut structure_or_table, &mut err_trunk) };
            if !res.is_ok() {
                return Err(err_trunk);
            }
        }

        let struct_def = if structure_or_table.is_null() {
            None
        } else {
            let res = RfcDecodedFieldDesc::from_handle(structure_or_table)?;
            Some(res)
        };

        Ok(RfcParameter {
            index,
            name: name_s,
            field_type: self.field_type,
            direction: self.direction,
            len: self.uc_length,
            struct_def,
            default_value,
            optional: self.optional != 0,
            fun,
            structure_or_table,
            p1: PhantomData,
            p2: PhantomData,
        })
    }
}

/// One RFC funciton parameter. This could be an IMPORTING, EXPORTING, CHANGING or TABLE parameter.
#[derive(Debug)]
pub struct RfcParameter<'conn, 'strct: 'conn> {
    pub index: u32,
    pub name: String,
    pub field_type: RfcType,
    pub direction: RfcDirection,
    pub len: u32,
    struct_def: Option<RfcDecodedFieldDesc<'conn, 'strct>>,
    default_value: Option<String>,
    optional: bool,
    fun: *mut RfcDataContainerHandle,
    structure_or_table: *mut RfcDataContainerHandle,
    p1: PhantomData<&'conn RfcConnectionHandle>,
    p2: PhantomData<&'strct RfcDataContainerHandle>,
}

impl<'conn, 'strct: 'conn> RfcDecodedFieldDesc<'conn, 'strct> {
    pub fn from_handle(
        handle: *mut RfcDataContainerHandle,
    ) -> Result<RfcDecodedFieldDesc<'conn, 'strct>, RfcErrorInfo> {
        let mut count: u32 = 0;
        let mut err_trunk = RfcErrorInfo::new();

        let type_handle = unsafe { RfcDescribeType(handle, &mut err_trunk) };
        if type_handle.is_null() {
            return Err(err_trunk);
        }

        {
            let res = unsafe { RfcGetFieldCount(type_handle, &mut count, &mut err_trunk) };
            if !res.is_ok() {
                return Err(err_trunk);
            }
        }
        let mut fields = Vec::new();
        let mut parameters = Vec::new();
        {
            let mut rfc_field_desc = RfcFieldDesc::new();
            for i in 0..count {
                let res = unsafe {
                    RfcGetFieldDescByIndex(type_handle, i, &mut rfc_field_desc, &mut err_trunk)
                };
                parameters.push(rfc_field_desc.to_parameter(i, handle)?);
                if !res.is_ok() {
                    return Err(err_trunk);
                }
                let name = unsafe {
                    U16CString::from_ptr_with_nul(rfc_field_desc.name.as_ptr(), 31)
                        .unwrap()
                        .to_string_lossy()
                };
                let sub_fields = if rfc_field_desc.type_desc_handle.is_null() {
                    None
                } else {
                    let d = RfcDecodedFieldDesc::from_handle(rfc_field_desc.type_desc_handle)?;
                    Some(Box::new(d))
                };
                let field = RfcDecodedField {
                    name,
                    index: i,
                    len: rfc_field_desc.uc_length,
                    field_type: rfc_field_desc.field_type,
                    sub_fields,
                    phantom: PhantomData,
                };
                fields.push(field);
            }
        }

        Ok(RfcDecodedFieldDesc { fields, parameters })
    }
}

#[derive(Debug)]
pub struct RfcDecodedField<'conn, 'strct: 'conn> {
    name: String,
    index: u32,
    len: u32,
    field_type: RfcType,
    sub_fields: Option<Box<RfcDecodedFieldDesc<'conn, 'strct>>>,
    phantom: PhantomData<&'strct RfcDataContainerHandle>,
}

impl RfcErrorInfo {
    pub fn new() -> RfcErrorInfo {
        RfcErrorInfo {
            code: RfcRc::RfcOk,
            group: RfcErrorGroup::Ok,
            key: [0 as u16; 128],
            message: [0 as u16; 512],
            abap_msg_class: [0 as u16; 21],
            abap_msg_type: [0 as u16; 2],
            abap_msg_number: [0 as u16; 4],
            abap_msg_v1: [0 as u16; 51],
            abap_msg_v2: [0 as u16; 51],
            abap_msg_v3: [0 as u16; 51],
            abap_msg_v4: [0 as u16; 51],
        }
    }

    pub fn custom(msg: &str) -> RfcErrorInfo {
        let mut err_trunk = RfcErrorInfo::new();
        let msg_enc = U16CString::from_str(msg).unwrap();
        let msg_enc = msg_enc.into_vec_with_nul();
        let len = min(err_trunk.message.len(), msg_enc.len());
        unsafe {
            std::ptr::copy(msg_enc.as_ptr(), err_trunk.message.as_mut_ptr(), len);
        }

        err_trunk.code = RfcRc::RfcCaiberp;
        err_trunk.group = RfcErrorGroup::CaiberP;
        err_trunk
    }
}

impl<'conn, 'strct: 'conn> RfcParameter<'conn, 'strct> {
    pub fn append_rows(&self, count: u32) -> Result<(), RfcErrorInfo> {
        self.field_type.ensure_table()?;
        let mut err_trunk = RfcErrorInfo::new();
        let res = unsafe { RfcAppendNewRows(self.structure_or_table, count, &mut err_trunk) };
        if res.is_ok() {
            Ok(())
        } else {
            Err(err_trunk)
        }
    }

    pub fn first_row(&self) -> Result<(), RfcErrorInfo> {
        self.field_type.ensure_table()?;
        let mut err_trunk = RfcErrorInfo::new();
        let res = unsafe { RfcMoveToFirstRow(self.structure_or_table, &mut err_trunk) };
        if res.is_ok() {
            Ok(())
        } else {
            Err(err_trunk)
        }
    }

    pub fn next_row(&self) -> Result<(), RfcErrorInfo> {
        self.field_type.ensure_table()?;
        let mut err_trunk = RfcErrorInfo::new();
        let res = unsafe { RfcMoveToNextRow(self.structure_or_table, &mut err_trunk) };
        if res.is_ok() {
            Ok(())
        } else {
            Err(err_trunk)
        }
    }

    pub fn previous_row(&self) -> Result<(), RfcErrorInfo> {
        self.field_type.ensure_table()?;
        let mut err_trunk = RfcErrorInfo::new();
        let res = unsafe { RfcMoveToPreviousRow(self.structure_or_table, &mut err_trunk) };
        if res.is_ok() {
            Ok(())
        } else {
            Err(err_trunk)
        }
    }

    pub fn last_row(&self) -> Result<(), RfcErrorInfo> {
        self.field_type.ensure_table()?;
        let mut err_trunk = RfcErrorInfo::new();
        let res = unsafe { RfcMoveToLastRow(self.structure_or_table, &mut err_trunk) };
        if res.is_ok() {
            Ok(())
        } else {
            Err(err_trunk)
        }
    }

    pub fn set_row(&self, index: u32) -> Result<(), RfcErrorInfo> {
        self.field_type.ensure_table()?;
        let mut err_trunk = RfcErrorInfo::new();
        let res = unsafe { RfcMoveTo(self.structure_or_table, index, &mut err_trunk) };
        if res.is_ok() {
            Ok(())
        } else {
            Err(err_trunk)
        }
    }

    pub fn get_row_count(&self) -> Result<u32, RfcErrorInfo> {
        self.field_type.ensure_table()?;
        let mut err_trunk = RfcErrorInfo::new();
        let mut row_count = 0;
        let res =
            unsafe { RfcGetRowCount(self.structure_or_table, &mut row_count, &mut err_trunk) };
        if res.is_ok() {
            Ok(row_count)
        } else {
            Err(err_trunk)
        }
    }

    pub fn get_field_count(&self) -> Result<u32, RfcErrorInfo> {
        self.field_type.ensure_table()?;
        self.struct_def
            .as_ref()
            .ok_or(RfcErrorInfo::custom("logic error at 01BC"))
            .map(|s| s.parameters.len() as u32)
    }

    pub fn get_field_index_by_name(&mut self, key: &str) -> Result<u32, RfcErrorInfo> {
        self.field_type.ensure_struct_or_table()?;
        let rpd = self
            .struct_def
            .as_mut()
            .ok_or(RfcErrorInfo::custom("Logic error at 01D4"))?;
        let mut i = 0;
        for field in &rpd.fields {
            if field.name.as_str().eq(key) {
                return Ok(i);
            }
            i += 1;
        }
        Err(RfcErrorInfo::custom("Unknown field"))
    }

    pub fn get_field_by_index(
        &self,
        index: u32,
    ) -> Result<&RfcParameter<'conn, 'strct>, RfcErrorInfo> {
        self.field_type.ensure_struct_or_table()?;
        let rpd = self
            .struct_def
            .as_ref()
            .ok_or(RfcErrorInfo::custom("Logic error at 01D4"))?;
        rpd.parameters
            .get(index as usize)
            .ok_or(RfcErrorInfo::custom("illegal index"))
    }

    pub fn get_field_by_index_mut(
        &mut self,
        index: u32,
    ) -> Result<&mut RfcParameter<'conn, 'strct>, RfcErrorInfo> {
        self.field_type.ensure_struct_or_table()?;
        let rpd = self
            .struct_def
            .as_mut()
            .ok_or(RfcErrorInfo::custom("Logic error at 01D4"))?;
        rpd.parameters
            .get_mut(index as usize)
            .ok_or(RfcErrorInfo::custom("illegal index"))
    }

    pub fn set_string(&mut self, value: &str) -> Result<(), RfcErrorInfo> {
        if !self.direction.can_write() {
            return Err(RfcErrorInfo::custom("Read-only parameter"));
        }
        if &self.field_type == &RfcType::String || &self.field_type == &RfcType::Char {
            let v = U16CString::from_str(value);
            if let Err(e) = v {
                return Err(RfcErrorInfo::custom(&e.to_string()));
            }
            let v = v.unwrap();
            let mut err_trunk = RfcErrorInfo::new();
            let v = v.into_vec_with_nul();
            let res = unsafe {
                RfcSetCharsByIndex(
                    self.fun,
                    self.index,
                    v.as_ptr(),
                    value.len() as u32,
                    &mut err_trunk,
                )
            };
            if !res.is_ok() {
                return Err(err_trunk);
            }
            Ok(())
        } else {
            Err(RfcErrorInfo::custom(
                "Not a string datatype, cannot use set_string",
            ))
        }
    }

    pub fn set_int(&mut self, value: i64) -> Result<(), RfcErrorInfo> {
        if !self.direction.can_write() {
            return Err(RfcErrorInfo::custom("Read-only parameter"));
        }
        let mut err_trunk = RfcErrorInfo::new();
        let res = unsafe { RfcSetIntByIndex(self.fun, self.index, value, &mut err_trunk) };
        if !res.is_ok() {
            return Err(err_trunk);
        }
        Ok(())
    }

    pub fn get_chars(&self) -> Result<String, RfcErrorInfo> {
        if !self.direction.can_read() {
            return Err(RfcErrorInfo::custom("Read-only parameter"));
        }

        /*
        if &self.field_type != &RfcType::String && &self.field_type != &RfcType::XString {
            return Err(RfcErrorInfo::custom(
                "Not of type STRING or XSTRING; cannot use get_string",
            ));
        }
        */

        let mut err_trunk = RfcErrorInfo::new();
        let mut buf = Vec::new();
        let mut reserve_len = self.len;
        reserve_len += 1;
        buf.reserve_exact(reserve_len as usize * 2);
        {
            let res = unsafe {
                RfcGetCharsByIndex(
                    self.fun,
                    self.index,
                    buf.as_mut_ptr(),
                    reserve_len,
                    &mut err_trunk,
                )
            };
            if !res.is_ok() {
                return Err(err_trunk);
            }
        }
        let s = unsafe { U16CString::from_ptr(buf.as_ptr() as *const u16, reserve_len as usize) };
        if let Err(e) = s {
            return Err(RfcErrorInfo::custom(&e.to_string()));
        }
        let s = s.unwrap().to_string();
        if let Err(e) = s {
            return Err(RfcErrorInfo::custom(&e.to_string()));
        }
        let s = s.unwrap();
        Ok(s)
    }

    pub fn get_string(&self) -> Result<String, RfcErrorInfo> {
        if !self.direction.can_read() {
            return Err(RfcErrorInfo::custom("Read-only parameter"));
        }

        /*
        if &self.field_type != &RfcType::String && &self.field_type != &RfcType::XString {
            return Err(RfcErrorInfo::custom(
                "Not of type STRING or XSTRING; cannot use get_string",
            ));
        }
        */

        let mut err_trunk = RfcErrorInfo::new();
        let mut buf = Vec::new();
        let mut reserve_len = 0;
        {
            let res = unsafe {
                RfcGetStringLengthByIndex(self.fun, self.index, &mut reserve_len, &mut err_trunk)
            };
            if !res.is_ok() {
                return Err(err_trunk);
            }
        }
        // This is an ungenau wissenschaft; utterly undocumented how to properly
        // use this API.
        reserve_len += 1;
        buf.reserve_exact(reserve_len as usize * 2);
        let mut len = 0;
        {
            let res = unsafe {
                RfcGetStringByIndex(
                    self.fun,
                    self.index,
                    buf.as_mut_ptr(),
                    reserve_len,
                    &mut len,
                    &mut err_trunk,
                )
            };
            if !res.is_ok() {
                return Err(err_trunk);
            }
        }
        let s = unsafe { U16CString::from_ptr(buf.as_ptr() as *const u16, len as usize) };
        if let Err(e) = s {
            return Err(RfcErrorInfo::custom(&e.to_string()));
        }
        let s = s.unwrap().to_string();
        if let Err(e) = s {
            return Err(RfcErrorInfo::custom(&e.to_string()));
        }
        let s = s.unwrap();
        Ok(s)
    }

    pub fn set_xstring(&mut self, v: &[u8]) -> Result<(), RfcErrorInfo> {
        if !self.direction.can_write() {
            return Err(RfcErrorInfo::custom("Read-only parameter"));
        }
        if &self.field_type != &RfcType::XString {
            return Err(RfcErrorInfo::custom(
                "Not of type XSTRING; cannot use get_xstring",
            ));
        }

        let mut err_trunk = RfcErrorInfo::new();
        let res = unsafe {
            RfcSetXStringByIndex(
                self.fun,
                self.index,
                v.as_ptr(),
                v.len() as u32,
                &mut err_trunk,
            )
        };
        if res.is_ok() {
            Ok(())
        } else {
            Err(err_trunk)
        }
    }

    pub fn get_xstring(&self) -> Result<Vec<u8>, RfcErrorInfo> {
        if !self.direction.can_read() {
            return Err(RfcErrorInfo::custom("Read-only parameter"));
        }
        if &self.field_type != &RfcType::XString {
            return Err(RfcErrorInfo::custom(
                "Not of type XSTRING; cannot use get_xstring",
            ));
        }
        let mut err_trunk = RfcErrorInfo::new();
        let mut reserve_len = 0;
        {
            let res = unsafe {
                RfcGetStringLengthByIndex(self.fun, self.index, &mut reserve_len, &mut err_trunk)
            };
            if !res.is_ok() {
                return Err(err_trunk);
            }
        }
        let mut out_len = 0;
        let mut out_buf = Vec::new();
        out_buf.reserve_exact(reserve_len as usize);
        unsafe {
            out_buf.set_len(reserve_len as usize);
        }
        let res = unsafe {
            RfcGetXStringByIndex(
                self.fun,
                self.index,
                out_buf.as_mut_ptr(),
                reserve_len,
                &mut out_len,
                &mut err_trunk,
            )
        };
        if res.is_ok() {
            Ok(out_buf)
        } else {
            Err(err_trunk)
        }
    }
}

#[link(name = "sapnwrfc")]
#[allow(dead_code)]
extern "C" {
    pub fn RfcOpenConnection(
        parameters: *const RfcConnectionParameter,
        param_count: u32,
        error: *mut RfcErrorInfo,
    ) -> *mut RfcConnectionHandle;

    pub fn RfcGetFunctionDesc(
        handle: *mut RfcConnectionHandle,
        func_name: *const u16,
        error: *mut RfcErrorInfo,
    ) -> *mut RfcFunctionDescHandle;

    pub fn RfcCreateFunction(
        handle: *mut RfcFunctionDescHandle,
        error: *mut RfcErrorInfo,
    ) -> *mut RfcDataContainerHandle;

    pub fn RfcGetCharsByIndex(
        handle: *mut RfcDataContainerHandle,
        index: u32,
        value: *mut u16,
        length: u32,
        error: *mut RfcErrorInfo,
    ) -> RfcRc;

    pub fn RfcSetCharsByIndex(
        handle: *mut RfcDataContainerHandle,
        index: u32,
        value: *const u16,
        length: u32,
        error: *mut RfcErrorInfo,
    ) -> RfcRc;

    pub fn RfcSetIntByIndex(
        handle: *mut RfcDataContainerHandle,
        index: u32,
        value: i64,
        error: *mut RfcErrorInfo,
    ) -> RfcRc;

    pub fn RfcInvoke(
        handle: *mut RfcConnectionHandle,
        fun: *mut RfcDataContainerHandle,
        error: *mut RfcErrorInfo,
    ) -> RfcRc;

    pub fn RfcGetStructureByIndex(
        fun: *const RfcDataContainerHandle,
        index: u32,
        structure: *mut *mut RfcDataContainerHandle,
        error: *mut RfcErrorInfo,
    ) -> RfcRc;

    pub fn RfcGetTableByIndex(
        fun: *const RfcDataContainerHandle,
        index: u32,
        table: *mut *mut RfcDataContainerHandle,
        error: *mut RfcErrorInfo,
    ) -> RfcRc;

    pub fn RfcGetStringByIndex(
        fun: *const RfcDataContainerHandle,
        index: u32,
        buf: *mut u8,
        len: u32,
        out_len: *mut u32,
        error: *mut RfcErrorInfo,
    ) -> RfcRc;

    pub fn RfcGetStringLengthByIndex(
        fun: *const RfcDataContainerHandle,
        index: u32,
        len: *mut u32,
        error: *mut RfcErrorInfo,
    ) -> RfcRc;

    pub fn RfcSetXStringByIndex(
        fun: *const RfcDataContainerHandle,
        index: u32,
        value: *const u8,
        len: u32,
        error: *mut RfcErrorInfo,
    ) -> RfcRc;

    pub fn RfcGetXStringByIndex(
        fun: *const RfcDataContainerHandle,
        index: u32,
        value: *mut u8,
        buflen: u32,
        reslen: *mut u32,
        error: *mut RfcErrorInfo,
    ) -> RfcRc;

    pub fn RfcDescribeType(
        fun: *const RfcDataContainerHandle,
        error: *mut RfcErrorInfo,
    ) -> *mut RfcDataContainerHandle;

    pub fn RfcGetFieldCount(
        tdh: *const RfcDataContainerHandle,
        count: *mut u32,
        error: *mut RfcErrorInfo,
    ) -> RfcRc;

    pub fn RfcGetParameterCount(
        fd: *const RfcFunctionDescHandle,
        count: *mut u32,
        error: *mut RfcErrorInfo,
    ) -> RfcRc;

    pub fn RfcGetFieldDescByIndex(
        tdh: *const RfcDataContainerHandle,
        index: u32,
        field_desc: *mut RfcFieldDesc,
        error: *mut RfcErrorInfo,
    ) -> RfcRc;

    pub fn RfcGetParameterDescByIndex(
        fh: *const RfcFunctionDescHandle,
        index: u32,
        param_desc: *mut RfcParameterDesc,
        error: *mut RfcErrorInfo,
    ) -> RfcRc;

    pub fn RfcDestroyFunction(
        handle: *mut RfcDataContainerHandle,
        error: *mut RfcErrorInfo,
    ) -> RfcRc;

    pub fn RfcMoveToFirstRow(
        handle: *mut RfcDataContainerHandle,
        error: *mut RfcErrorInfo,
    ) -> RfcRc;

    pub fn RfcMoveToLastRow(handle: *mut RfcDataContainerHandle, error: *mut RfcErrorInfo)
        -> RfcRc;

    pub fn RfcMoveToNextRow(handle: *mut RfcDataContainerHandle, error: *mut RfcErrorInfo)
        -> RfcRc;

    pub fn RfcMoveToPreviousRow(
        handle: *mut RfcDataContainerHandle,
        error: *mut RfcErrorInfo,
    ) -> RfcRc;

    pub fn RfcMoveTo(
        handle: *mut RfcDataContainerHandle,
        index: u32,
        error: *mut RfcErrorInfo,
    ) -> RfcRc;

    pub fn RfcGetRowCount(
        handle: *mut RfcDataContainerHandle,
        row_count: *mut u32,
        error: *mut RfcErrorInfo,
    ) -> RfcRc;

    pub fn RfcAppendNewRows(
        handle: *mut RfcDataContainerHandle,
        row_count: u32,
        error: *mut RfcErrorInfo,
    ) -> RfcRc;

    pub fn RfcCloseConnection(handle: *mut RfcConnectionHandle, error: *mut RfcErrorInfo) -> RfcRc;
}
