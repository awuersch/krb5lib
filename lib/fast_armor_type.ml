(** {{https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-5} Fast Armor Types, Last updated 2017-03-02} *)
module M = struct
  type t =
    | Reserved_0               (* rfc6113 *)
    | FX_FAST_ARMOR_AP_REQUEST (* rfc6113 *)
    [@@deriving sexp]

  let alist =
    [ Reserved_0, 0, "Reserved_0"
    ; FX_FAST_ARMOR_AP_REQUEST, 1, "FX_FAST_ARMOR_AP_REQUEST"
    ]
end

module Asn1 = Krb_int32.Of_alist(M)
include Asn1
