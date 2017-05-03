open Sexplib.Std

type t = int32 [@@deriving sexp]

module Ast = struct
  type t = Z.t

  let asn = Asn.S.integer
end

let ast_of_t = Z.of_int32

let t_of_ast = Z.to_int32

module Of_alist (M : Interfaces.ALIST) : Asn1_intf.S with type t = M.t = struct
  include M

  module Ast = Ast

  module Intable = Interfaces.Intable_of_alist(M)

  let ast_of_t t = Z.of_int (Intable.int_of_t t)

  let t_of_ast ast = Intable.t_of_int (Z.to_int ast)
end
