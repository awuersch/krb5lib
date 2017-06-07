module Flags = struct
  type t =
  | Reserved_0
  | Use_session_key
  | Mutual_required
  [@@deriving sexp]

  let alist =
    [ Reserved_0, 0, "Reserved_0"
    ; Use_session_key, 1, "Use_session_key"
    ; Mutual_required, 2, "Mutual_required"
    ]

  module Encoding_options = struct
    let min_bits = 32
  end
end

include Krb_combinators.Make_flags_alist(Flags)
