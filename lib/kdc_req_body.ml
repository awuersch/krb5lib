open Sexplib.Std
open Asn.S
open Krb_combinators

(* CR bbohrer: Encode invariant that cname is only used for as-req *)
type t =
  { kdc_options : Kdc_options.t
  ; cname : Principal_name.t option (* Used only in As-req *)
  ; realm : Realm.t
  ; sname : Principal_name.t option
  ; from : Kerberos_time.t option
  ; till : Kerberos_time.t
  ; rtime : Kerberos_time.t option
  ; nonce : Uint32.t
  ; etype : Encryption_type.t list (* In preference order*)
  ; addresses : Host_addresses.t option
  ; enc_authorization_data : Encrypted_data.t option
  ; additional_tickets :  Ticket.t list
  } [@@deriving sexp]

module Ast = struct
  type t =
      Kdc_options.Ast.t
    * (Principal_name.Ast.t option (* Used only in As-req *)
    * (Realm.Ast.t
    * (Principal_name.Ast.t option
    * (Kerberos_time.Ast.t option
    * (Kerberos_time.Ast.t
    * (Kerberos_time.Ast.t option
    * (Uint32.Ast.t
    * (Encryption_type.Ast.t list (* In preference order*)
    * (Host_addresses.Ast.t option
    * (Encrypted_data.Ast.t option
    *  Ticket.Ast.t list option))))))))))

  let asn =
    sequence
       ( tag_required 0 ~label:"kdc_options" Kdc_options.Ast.asn
       @ tag_optional 1 ~label:"cname" Principal_name.Ast.asn
       @ tag_required 2 ~label:"realm" Realm.Ast.asn
       @ tag_optional 3 ~label:"sname" Principal_name.Ast.asn
       @ tag_optional 4 ~label:"from" Kerberos_time.Ast.asn
       @ tag_required 5 ~label:"till" Kerberos_time.Ast.asn
       @ tag_optional 6 ~label:"rtime" Kerberos_time.Ast.asn
       @ tag_required 7 ~label:"nonce" Uint32.Ast.asn
       @ tag_required 8 ~label:"etype" (sequence_of Encryption_type.Ast.asn)
       @ tag_optional 9 ~label:"addresses" Host_addresses.Ast.asn
       @ tag_optional 10 ~label:"enc_authorization_data" Encrypted_data.Ast.asn
      -@ tag_optional 11 ~label:"additional_tickets" (sequence_of Ticket.Ast.asn))
end

let ast_of_t t =
  let additional_tickets =
    match t.additional_tickets with
    | [] -> None
    | lst -> Some (List.map Ticket.ast_of_t lst)
  in
  (Kdc_options.ast_of_t t.kdc_options,
  (Option.map ~f:Principal_name.ast_of_t t.cname,
  (Realm.ast_of_t t.realm,
  (Option.map ~f:Principal_name.ast_of_t t.sname,
  (Option.map ~f:Kerberos_time.ast_of_t t.from,
  (Kerberos_time.ast_of_t t.till,
  (Option.map ~f:Kerberos_time.ast_of_t t.rtime,
  (Uint32.ast_of_t t.nonce,
  (List.map Encryption_type.ast_of_t t.etype,
  (Option.map ~f:Host_addresses.ast_of_t t.addresses,
  (Option.map ~f:Encrypted_data.ast_of_t t.enc_authorization_data,
   additional_tickets)))))))))))

let t_of_ast (a, (b, (c, (d, (e, (f, (g, (h, (i, (j, (k, l))))))))))) =
  { kdc_options = Kdc_options.t_of_ast a
  ; cname = Option.map ~f:Principal_name.t_of_ast b
  ; realm = Realm.t_of_ast c
  ; sname = Option.map ~f:Principal_name.t_of_ast d
  ; from = Option.map ~f:Kerberos_time.t_of_ast e
  ; till = Kerberos_time.t_of_ast f
  ; rtime = Option.map ~f:Kerberos_time.t_of_ast g
  ; nonce = Uint32.t_of_ast h
  ; etype = List.map Encryption_type.t_of_ast i
  ; addresses = Option.map ~f:Host_addresses.t_of_ast j
  ; enc_authorization_data = Option.map ~f:Encrypted_data.t_of_ast k
  ; additional_tickets = match l with
    | None -> []
    | Some lst -> List.map Ticket.t_of_ast lst
  }
