Rust bindings to SAP's NW RFC library. This library aims to build safe
bindings. This means that no operations are allowed that cause
undefined behavior or access violations. This is, however, a
notoriously difficult undertaking when dealing with APIs to unsafe
languages such as C++.

If you find bugs or have feature improvements, you are very welcome to
submit pull requests! Also, please do not hesitate to discuss ideas by
opening an issues or sending an e-mail to the author directly:
<hc-rsrfc@hcesperer.org>

Please see the LICENSE file for details about licensing. Please note
that the LICENSE covers only this RFC wrapper and not the original SAP
NW RFC library. The SAP NW RFC library is covered by SAP's proprietary
license.

## To use:

You need to download the SAP NW RFC library from SAP and put it in one of the
folders in saprfc/ for compliation.

For execution, you need to ensure LD_LIBRARY_PATH points to the RFC shared
library.

Please see the src/main.rs file for an example that calls
RFC_READ_TABLE to fetch a list of user names from the USR02 table.
(Something every SAP admin would love to see you do on their
production systems ;-) )

## What works:

* Calling RFC functions, setting and getting parameters, including
  table parameters.

## What doesn't work:

* Various datatypes don't have implementations yet.

* Structures and TABLEs are not as well-tested yet as simple data
  types such as STRINGs and XSTRINGs.

* Writing RFC servers.

