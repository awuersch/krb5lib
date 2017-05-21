open Sexplib.Std
open Asn.S
include Krb_combinators

type t =
  { tickets : Ticket.t list
  ; enc_part : Encrypted_data.t
  } [@@deriving sexp]

module Ast = struct
  type t =
      Z.t (* pvno - 5 *)
    * Z.t (* msg_type *)
    * Ticket.Ast.t list
    * Encrypted_data.Ast.t

  let asn =
    Application_tag.tag `Krb_cred
      (sequence4
         (tag_required 0 ~label:"pvno" integer)
         (tag_required 1 ~label:"msg-type" integer)
         (tag_required 2 ~label:"tickets" (sequence_of Ticket.Ast.asn))
         (tag_required 3 ~label:"enc-part" Encrypted_data.Ast.asn))
end

let ast_of_t t =
  ( Z.of_int 5 (* Where 5 means krb5 - this is a constant forever *)
  , Application_tag.int_of_t `Krb_cred |> Z.of_int
  , List.map Ticket.ast_of_t t.tickets
  , Encrypted_data.ast_of_t t.enc_part
  )

let t_of_ast : Ast.t -> t = function
  | (_, _, a, b) -> 
    { tickets = List.map Ticket.t_of_ast a
    ; enc_part = Encrypted_data.t_of_ast b
    }
