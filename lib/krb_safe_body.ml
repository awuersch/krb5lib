open Sexplib.Std
open Asn.S
include Krb_combinators

type t =
  { user_data : Octet_string.t
  ; timestamp : Kerberos_time.t option
  ; usec : Microseconds.t option
  ; seq_number : Uint32.t option
  ; s_address : Host_address.t
  ; r_address : Host_address.t option
  } [@@deriving sexp]

module Ast = struct
  type t =
    Octet_string.Ast.t
    * (Kerberos_time.Ast.t option
    * (Microseconds.Ast.t option
    * (Uint32.Ast.t option
    * (Host_address.Ast.t
    *  Host_address.Ast.t option))))

  let asn =
    sequence
     ( (tag_required 0 ~label:"user-data" Octet_string.Ast.asn)
     @ (tag_optional 1 ~label:"timestamp" Kerberos_time.Ast.asn)
     @ (tag_optional 2 ~label:"usec" Microseconds.Ast.asn)
     @ (tag_optional 3 ~label:"usec" Uint32.Ast.asn)
     @ (tag_required 4 ~label:"s-address" Host_address.Ast.asn)
    -@ (tag_optional 5 ~label:"r-address" Host_address.Ast.asn))
end

let ast_of_t t =
   (Octet_string.ast_of_t t.user_data
  ,(Option.map ~f:Kerberos_time.ast_of_t t.timestamp
  ,(Option.map ~f:Microseconds.ast_of_t t.usec
  ,(Option.map ~f:Uint32.ast_of_t t.seq_number
  ,(Host_address.ast_of_t t.s_address
  , Option.map ~f:Host_address.ast_of_t t.r_address)))))

let t_of_ast (a, (b, (c, (d, (e, f))))) =
  { user_data = Octet_string.t_of_ast a
  ; timestamp = Option.map ~f:Kerberos_time.t_of_ast b
  ; usec = Option.map ~f:Microseconds.t_of_ast c
  ; seq_number = Option.map ~f:Uint32.t_of_ast d
  ; s_address = Host_address.t_of_ast e
  ; r_address = Option.map ~f:Host_address.t_of_ast f
  }
