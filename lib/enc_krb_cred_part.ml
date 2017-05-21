open Sexplib.Std
open Asn.S
include Krb_combinators

type t =
  { ticket_info : Krb_cred_info.t list
  ; nonce : Uint32.t option
  ; timestamp : Kerberos_time.t option
  ; usec : Microseconds.t option
  ; s_address : Host_address.t option
  ; r_address : Host_address.t option
  } [@@deriving sexp]

module Ast = struct
  type t =
    Krb_cred_info.Ast.t list
    * (Uint32.Ast.t option
    * (Kerberos_time.Ast.t option
    * (Microseconds.Ast.t option
    * (Host_address.Ast.t option
    *  Host_address.Ast.t option))))

  let asn =
    Application_tag.tag `Enc_krb_cred_part
      (sequence
        ( (tag_required 0 ~label:"ticket-info" (sequence_of Krb_cred_info.Ast.asn))
        @ (tag_optional 1 ~label:"nonce" Uint32.Ast.asn)
        @ (tag_optional 2 ~label:"timestamp" Kerberos_time.Ast.asn)
        @ (tag_optional 3 ~label:"usec" Microseconds.Ast.asn)
        @ (tag_optional 4 ~label:"s-address" Host_address.Ast.asn)
       -@ (tag_optional 5 ~label:"r-address" Host_address.Ast.asn)))
end

let ast_of_t t =
   (List.map Krb_cred_info.ast_of_t t.ticket_info
  ,(Option.map Uint32.ast_of_t t.nonce
  ,(Option.map Kerberos_time.ast_of_t t.timestamp
  ,(Option.map Microseconds.ast_of_t t.usec
  ,(Option.map Host_address.ast_of_t t.s_address
  , Option.map Host_address.ast_of_t t.r_address)))))

let t_of_ast (a, (b, (c, (d, (e, f))))) =
  { ticket_info = List.map Krb_cred_info.t_of_ast a
  ; nonce = Option.map Uint32.t_of_ast b
  ; timestamp = Option.map Kerberos_time.t_of_ast c
  ; usec = Option.map Microseconds.t_of_ast d
  ; s_address = Option.map Host_address.t_of_ast e
  ; r_address = Option.map Host_address.t_of_ast f
  }
