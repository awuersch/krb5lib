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
    [ Ipv4, 2, "Ipv4"
    ; Directional, 3, "Directional"
    ; Chaos_net, 5, "Chaos_net"
    ; Xns, 6, "Xns"
    ; Iso, 7, "Iso"
    ; Decnet_phase_iv, 12, "Decnet_phase_iv"
    ; Apple_talk_ddp, 16, "Apple_talk_ddp"
    ; Net_bios, 20, "Net_bios"
    ; Ipv6, 24, "Ipv6"
    ]
end

module Asn1 = Krb_int32.Of_alist (M)
include Asn1
