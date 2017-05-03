open Sexplib.Std

type ty =
| Unknown
| Principal
| Srv_inst
| Srv_hst
| Srv_xhst
| Uid
| X500_principal
| Smtp_name
| Enterprise
[@@deriving sexp]

module Alist = struct
  type nonrec t = ty

  let alist =
    [ Unknown, 0
    ; Principal, 1
    ; Srv_inst, 2
    ; Srv_hst, 3
    ; Srv_xhst, 4
    ; Uid, 5
    ; X500_principal, 6
    ; Smtp_name, 7
    ; Enterprise, 10
    ]
end

module Asn1 = Krb_int32.Of_alist (Alist)

include Asn1
