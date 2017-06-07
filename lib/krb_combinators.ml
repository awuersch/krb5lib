open Sexplib.Conv
open Asn.S
open Interfaces

(* ?cls:None specifies Context-specific ASN tags, which we use a lot *)
let tag_required tag ?label t = (required ?label (explicit ?cls:None tag t))
let tag_optional tag ?label t = (optional ?label (explicit ?cls:None tag t))

module type FLAG_SPEC = sig
  include ALIST
  module Encoding_options : sig
    val min_bits : int
  end
end

module Make_flags_alist (M : FLAG_SPEC) = struct
  let () = assert (M.Encoding_options.min_bits >= 0)

  module Intable = Intable_of_alist(M)
  module OrderedType = OrderedType_of_Intable(Intable)
  module Encoding_options = M.Encoding_options
  module FlagSet = Set.Make(OrderedType)

  type t = FlagSet.t

  module Ast = struct
    type t = bool array

    let asn = bit_string
  end

  let ast_of_t t =
    let string_size =
      if FlagSet.is_empty t then
        Encoding_options.min_bits
      else
        min
          (Intable.int_of_t (FlagSet.min_elt t))
          Encoding_options.min_bits
    in
    let bit_string = Array.make string_size false in
    FlagSet.iter (fun flag -> bit_string.(Intable.int_of_t flag) <- true) t;
    bit_string

  let t_of_ast ast =
    let add (t, i) b =
      let t =
        if b then FlagSet.add (Intable.t_of_int i) t else t
      in
        t, succ i
    in
      let t, _ = Array.fold_left add (FlagSet.empty, 0) ast in t
  
  let sexp_of_t t = 
    let cons flag l = (Intable.int_of_t flag) :: l in
    let il = FlagSet.fold cons t [] |> List.rev in
      sexp_of_list sexp_of_int il

  let t_of_sexp sexp =
    let add s i = 
      let flag = Intable.t_of_int i in
        FlagSet.add flag s
    in
      list_of_sexp int_of_sexp sexp |> List.fold_left add FlagSet.empty
end
