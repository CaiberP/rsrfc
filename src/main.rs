extern crate rsrfc;

use rsrfc::*;
use rsrfc::error::RfcErrorInfo;

fn main() -> Result<(), RfcErrorInfo>{
    let conn_params = RfcConnectionParameters {
        ashost: "192.168.8.4",
        sysnr: "00",
        client: "001",
        user: "bobpage",
        passwd: "Maggie8+Chow%-!",
        lang: "EN",
    };

    // Open the rfc dll or .so
    let rfc_dll = RfcLib::new().expect("Unable to open the rfc lib");

    // Establish an RFC connection. If you need to supply more parameters than
    // those supported by RfcConnectionParameters, simply call
    // RfcConnection::from_hashmap instead.
    let conn = RfcConnection::new(&conn_params, &rfc_dll);
    let conn = match conn {
        Err(e) => {
            eprintln!("oops {:?}", e);
            return Err(e);
        }
        Ok(c) => c
    };

    eprintln!("Fetching user names...");
    {
        // Get the RFC_READ_TABLE function
        let mut rfc_read_table = conn.get_function("RFC_READ_TABLE").expect("RFC_READ_TABLE");
        {
            let query_table = rfc_read_table
                .get_mut_parameter("QUERY_TABLE")
                .ok_or(RfcErrorInfo::custom("unknown field QUERY_TABLE"))?;
            query_table.set_string("USR02")?;
        }

        // The field we are interested in is called BNAME.
        // Tell this to the RFC_READ_TABLE function.
        {
            let fields = rfc_read_table.get_mut_parameter("FIELDS")
            .ok_or(RfcErrorInfo::custom("unknown field FIELDNAME"))?;
            let idx_fieldname = fields
                .get_field_index_by_name("FIELDNAME")?;
            fields.append_rows(1)?;
            fields.first_row()?;
            let fieldname = fields
                .get_field_by_index(idx_fieldname)?;
            fieldname
                .set_string("BNAME")?;
        }

        // Call the function
        rfc_read_table.call()?;

        // Now the local data structures are filled with the response of the
        // remote function: retrieve the data
        let data = rfc_read_table.get_mut_parameter("DATA")
        .ok_or(RfcErrorInfo::custom("unknown field DATA"))?;
        // Get the intger index of the field to allow quicker access later
        let idx_wa = data.get_field_index_by_name("WA")?;
        let num_users = data.get_row_count()?;
        eprintln!(
            "Response from SAP has arrived: {} users.",
            num_users
        );
        for i in 0..num_users {
            data.set_row(i)?;
            let row_content = data
                .get_field_by_index(idx_wa)?
                .get_chars()?;
            println!("Username: {}", row_content.trim_end());
        }
    }

    Ok(())
}
