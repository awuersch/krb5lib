open Asn.S
include Krb_combinators

type t =
  { ap_options : Ap_options.t
  ; ticket : Ticket.t
  ; authenticator : Encrypted_data.t
  } [@@deriving sexp]

module Ast = struct
  type t =
      Z.t (* pvno - 5 *)
    * Z.t (* msg_type *)
    * Ap_options.Ast.t
    * Ticket.Ast.t
    * Encrypted_data.Ast.t

  let asn =
    Application_tag.tag `Ap_req
      (sequence5
         (tag_required 0 ~label:"pvno" integer)
         (tag_required 1 ~label:"msg-type" integer)
         (tag_required 2 ~label:"ap-options" Ap_options.Ast.asn)
         (tag_required 3 ~label:"ticket" Ticket.Ast.asn)
         (tag_required 4 ~label:"authenticator" Encrypted_data.Ast.asn))
end

let ast_of_t t =
  ( Z.of_int 5 (* Where 5 means krb5 - this is a constant forever *)
  , Application_tag.int_of_t `Ap_req |> Z.of_int
  , Ap_options.ast_of_t t.ap_options
  , Ticket.ast_of_t t.ticket
  , Encrypted_data.ast_of_t t.authenticator
  )

let t_of_ast : Ast.t -> t = function
  | (_, _, a, b, c) -> 
    { ap_options = Ap_options.t_of_ast a
    ; ticket = Ticket.t_of_ast b
    ; authenticator = Encrypted_data.t_of_ast c
    }
