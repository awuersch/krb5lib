open Sexplib.Std

module Flags = struct
  type t =
  | Reserved
  | Forwardable
  | Forwarded
  | Proxiable
  | Proxy
  | Allow_postdate
  | Postdated
  | Unused7
  | Renewable
  | Unused9
  | Unused10
  | Opt_hardware_auth
  | Unused12
  | Unused13
  | Unused15
  | Disable_transited_check
  | Renewable_ok
  | Ext_ticket_in_skey
  | Renew
  | Validate
  [@@deriving sexp]

  let alist =
    [ Reserved, 0
    ; Forwardable, 1
    ; Forwarded, 2
    ; Proxiable, 3
    ; Proxy, 4
    ; Allow_postdate, 5
    ; Postdated, 6
    ; Unused7, 7
    ; Renewable, 8
    ; Unused9, 9
    ; Unused10, 10
    ; Opt_hardware_auth, 11
    ; Unused12, 12
    ; Unused13, 13
    ; Unused15, 15
    ; Disable_transited_check, 26
    ; Renewable_ok, 27
    ; Ext_ticket_in_skey, 28
    ; Renew, 30
    ; Validate, 31
    ]

  module Encoding_options = struct
    let min_bits = 32
  end
end

include Krb_combinators.Make_flags_alist(Flags)
