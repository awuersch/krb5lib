open Sexplib.Std

(** {{https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-6} Fast Options, Last updated 2017-03-02} *)
module Flags = struct
  type t =
  | Reserved_0
  | Hide_client_names
  | Kdc_follow_referrals
  [@@deriving sexp]

  let alist =
    [ Reserved_0, 0, "Reserved_0"
    ; Hide_client_names, 1, "Hide_client_names"
    ; Kdc_follow_referrals, 16, "Kdc_follow_referrals"
    ]

  module Encoding_options = struct
    let min_bits = 32
  end
end

include Krb_combinators.Make_flags_alist(Flags)
