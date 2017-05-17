open Sexplib.Std

module Flags = struct
  type t =
  | Reserved_0
  | Forwardable
  | Forwarded
  | Proxiable
  | Proxy
  | May_postdate
  | Postdated
  | Invalid
  | Renewable
  | Initial
  | Pre_authent
  | Hw_authent
  | Transited_policy_checked
  | Ok_as_delegate
  [@@deriving sexp]

  let alist =
    [ Reserved_0, 0, "Reserved_0"
    ; Forwardable, 1, "Forwardable"
    ; Forwarded, 2, "Forwarded"
    ; Proxiable, 3, "Proxiable"
    ; Proxy, 4, "Proxy"
    ; May_postdate, 5, "May_postdate"
    ; Postdated, 6, "Postdated"
    ; Invalid, 7, "Invalid"
    ; Renewable, 8, "Renewable"
    ; Initial, 9, "Initial"
    ; Pre_authent, 10, "Pre_authent"
    ; Hw_authent, 11, "Hw_authent"
    ; Transited_policy_checked, 12, "Transited_policy_checked"
    ; Ok_as_delegate, 13, "Ok_as_delegate"
    ]

  module Encoding_options = struct
    let min_bits = 32
  end
end

include Krb_combinators.Make_flags_alist(Flags)
