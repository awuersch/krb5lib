open Sexplib.Std
open Asn.S
open Interfaces

(* ?cls:None specifies Context-specific ASN tags, which we use a lot*)
let tag_required tag ?label t = (required ?label (explicit ?cls:None tag t))
let tag_optional tag ?label t = (optional ?label (explicit ?cls:None tag t))

module type FLAG_TYPE = sig
  type t

  module Intable : Intable with type t = t
  module OrderedType : Set.OrderedType with type t = t

  module Encoding_options : sig
    (* Minimum number of bits to use when serializing a flag set *)
    val min_bits : int
  end
end

module Make_flags (Flag : FLAG_TYPE) : Asn1_intf.S
  with type t = Set.Make(Flag.OrderedType).t = struct
  let () = assert (Flag.Encoding_options.min_bits >= 0)

  module Flag_set = Set.Make(Flag.OrderedType)

  type t = Flag_set.t

  module Ast = struct
    type t = bool array

    let asn = bit_string
  end

  let ast_of_t t =
    let string_size =
      if Flag_set.is_empty t then
        Flag.Encoding_options.min_bits
      else
        min
          (Flag.Intable.int_of_t (Flag_set.min_elt t))
          Flag.Encoding_options.min_bits
    in
    let bit_string = Array.make string_size false in
    Flag_set.iter (fun flag -> bit_string.(Flag.Intable.int_of_t flag) <- true) t;
    bit_string

  let t_of_ast ast =
    let add (t, i) b =
      let t =
        if b then Flag_set.add (Flag.Intable.t_of_int i) t else t
      in
        t, succ i
    in
      let t, _ = Array.fold_left add (Flag_set.empty, 0) ast
  in
    t
end

module Make_flags_alist (M :
  sig
    include ALIST
    module Encoding_options : sig
      val min_bits : int
    end
  end) : Asn1_intf.S = struct

  module Arg : FLAG_TYPE = struct
    type t = M.t
    module Intable = Intable_of_alist(M)
    module OrderedType = OrderedType_of_Intable(Intable)
    module Encoding_options = M.Encoding_options
  end

  include Make_flags (Arg)
end
