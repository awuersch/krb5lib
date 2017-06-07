module M = struct
  type t =
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

  let alist =
    [ Unknown, 0, "Unknown"
    ; Principal, 1, "Principal"
    ; Srv_inst, 2, "Srv_inst"
    ; Srv_hst, 3, "Srv_hst"
    ; Srv_xhst, 4, "Srv_xhst"
    ; Uid, 5, "Uid"
    ; X500_principal, 6, "X500_principal"
    ; Smtp_name, 7, "Smtp_name"
    ; Enterprise, 10, "Enterprise"
    ]
end

module Asn1 = Krb_int32.Of_alist (M)
include Asn1
