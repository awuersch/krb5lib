open Sexplib.Std
open Asn.S
open Krb_combinators

type t =
  { patimestamp : Kerberos_time.t
  ; pausec : Microseconds.t option
  } [@@deriving sexp]

module Ast = struct
  type t = Kerberos_time.Ast.t * Microseconds.Ast.t option

  let asn =
    (sequence2
       (tag_required 0 ~label:"patimestamp" Kerberos_time.Ast.asn)
       (tag_optional 1 ~label:"pausec" Microseconds.Ast.asn))
end

let ast_of_t t =
  ( Kerberos_time.ast_of_t t.patimestamp
  , Option.map ~f:Microseconds.ast_of_t t.pausec )

let t_of_ast (a, b) =
  { patimestamp = Kerberos_time.t_of_ast a
  ; pausec = Option.map ~f:Microseconds.t_of_ast b
  }
