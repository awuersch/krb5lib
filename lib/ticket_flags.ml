open Sexplib.Std

module Flags : Interfaces.ALIST = struct
  type t =
  | Reserved
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
    [ Reserved, 0
    ; Forwardable, 1
    ; Forwarded, 2
    ; Proxiable, 3
    ; Proxy, 4
    ; May_postdate, 5
    ; Postdated, 6
    ; Invalid, 7
    ; Renewable, 8
    ; Initial, 9
    ; Pre_authent, 10
    ; Hw_authent, 11
    ; Transited_policy_checked, 12
    ; Ok_as_delegate, 13
    ]
end

include Krb_combinators.Make_flags_alist
  (struct
    include Flags
    module Encoding_options = struct
      let min_bits = 32
    end
   end)
