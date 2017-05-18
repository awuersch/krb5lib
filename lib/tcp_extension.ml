open Sexplib.Std

(** {{https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-3} Kerberos Tcp Extensions, Last updated 2017-03-02} *)
module M = struct
  type t =
    | Krb5_over_TLS (* rfc6251 *)
    | Reserved_0    (* rfc5021 *)
    [@@deriving sexp]

  let alist =
    [ Krb5_over_TLS, 0, "Krb5_over_TLS"
    ; Reserved_0   , 30, "Reserved_0"
    ]
end

module Asn1 = Krb_int32.Of_alist(M)
include Asn1
