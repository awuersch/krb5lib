module Flags = struct
  type t =
  | Reserved_0
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
    [ Reserved_0, 0, "Reserved_0"
    ; Forwardable, 1, "Forwardable"
    ; Forwarded, 2, "Forwarded"
    ; Proxiable, 3, "Proxiable"
    ; Proxy, 4, "Proxy"
    ; Allow_postdate, 5, "Allow_postdate"
    ; Postdated, 6, "Postdated"
    ; Unused7, 7, "Unused7"
    ; Renewable, 8, "Renewable"
    ; Unused9, 9, "Unused9"
    ; Unused10, 10, "Unused10"
    ; Opt_hardware_auth, 11, "Opt_hardware_auth"
    ; Unused12, 12, "Unused12"
    ; Unused13, 13, "Unused13"
    ; Unused15, 15, "Unused15"
    ; Disable_transited_check, 26, "Disable_transited_check"
    ; Renewable_ok, 27, "Renewable_ok"
    ; Ext_ticket_in_skey, 28, "Ext_ticket_in_skey"
    ; Renew, 30, "Renew"
    ; Validate, 31, "Validate"
    ]

  module Encoding_options = struct
    let min_bits = 32
  end
end

include Krb_combinators.Make_flags_alist(Flags)
