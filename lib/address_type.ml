open Sexplib.Std

module M = struct
  type t =
  | Ipv4
  | Directional
  | Chaos_net
  | Xns
  | Iso
  | Decnet_phase_iv
  | Apple_talk_ddp
  | Net_bios
  | Ipv6
  [@@deriving sexp]

  let alist =
    [ Ipv4, 2
    ; Directional, 3
    ; Chaos_net, 5
    ; Xns, 6
    ; Iso, 7
    ; Decnet_phase_iv, 12
    ; Apple_talk_ddp, 16
    ; Net_bios, 20
    ; Ipv6, 24
    ]
end

module Asn1 = Krb_int32.Of_alist (M)
include Asn1
