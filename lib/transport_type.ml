open Sexplib.Std

(** {{https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-9} Kerberos Message Transport Types, Last updated 2017-03-02} *)
module M = struct
  type t =
    | Reserved_0 (* rfc6784 *)
    | UDP        (* rfc6784 *)
    | TCP        (* rfc6784 *)
    | TLS        (* rfc6784 *)
    [@@deriving sexp]

  let alist =
    [ Reserved_0, 0, "Reserved_0"
    ; UDP       , 1, "UDP"
    ; TCP       , 2, "TCP"
    ; TLS       , 3, "TLS"
    ]
end

module Asn1 = Krb_int32.Of_alist(M)
include Asn1
