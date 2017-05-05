open Sexplib.Std

type t =
[ `Ticket
| `Authenticator
| `Enc_ticket_part
| `As_req
| `As_rep
| `Tgs_req
| `Tgs_rep
| `Ap_req
| `Ap_rep
| `Reserved16
| `Reserved17
| `Krb_safe
| `Krb_priv
| `Krb_cred
| `Enc_as_rep_part
| `Enc_tgs_rep_part
| `Enc_ap_rep_part
| `Enc_krb_priv_part
| `Enc_krb_cred_part
| `Krb_error
] [@@deriving sexp]

let int_of_t t =
  match t with
  | `Ticket -> 1
  | `Authenticator -> 2
  | `Enc_ticket_part -> 3
  | `As_req -> 10
  | `As_rep -> 11
  | `Tgs_req -> 12
  | `Tgs_rep -> 13
  | `Ap_req -> 14
  | `Ap_rep -> 15
  | `Reserved16 -> 16
  | `Reserved17 -> 17
  | `Krb_safe -> 20
  | `Krb_priv -> 21
  | `Krb_cred -> 22
  | `Enc_as_rep_part -> 25
  | `Enc_tgs_rep_part -> 26
  | `Enc_ap_rep_part -> 27
  | `Enc_krb_priv_part -> 28
  | `Enc_krb_cred_part -> 29
  | `Krb_error -> 30

let t_of_int_exn int =
  match int with
  | 1 -> `Ticket
  | 2 -> `Authenticator
  | 3 -> `Enc_ticket_part
  | 10 -> `As_req
  | 11 -> `As_rep
  | 12 -> `Tgs_req
  | 13 -> `Tgs_rep
  | 14 -> `Ap_req
  | 15 -> `Ap_rep
  | 16 -> `Reserved16
  | 17 -> `Reserved17
  | 20 -> `Krb_safe
  | 21 -> `Krb_priv
  | 22 -> `Krb_cred
  | 25 -> `Enc_as_rep_part
  | 26 -> `Enc_tgs_rep_part
  | 27 -> `Enc_ap_rep_part
  | 28 -> `Enc_krb_priv_part
  | 29 -> `Enc_krb_cred_part
  | 30 -> `Krb_error
  | _  -> `Krb_error
(*
  | _ -> failwith (Printf.sprintf "Invalid application tag number %d" int)
 *)

let tag t asn = Asn.S.explicit ~cls:`Application (int_of_t t) asn

let string_of_t t =
  match t with
  | `Ticket -> "Ticket"
  | `Authenticator -> "Authenticator"
  | `Enc_ticket_part -> "Enc_ticket_part"
  | `As_req -> "As_req"
  | `As_rep -> "As_rep"
  | `Tgs_req -> "Tgs_req"
  | `Tgs_rep -> "Tgs_rep"
  | `Ap_req -> "Ap_req"
  | `Ap_rep -> "Ap_rep"
  | `Reserved16 -> "Reserved16"
  | `Reserved17 -> "Reserved17"
  | `Krb_safe -> "Krb_safe"
  | `Krb_priv -> "Krb_priv"
  | `Krb_cred -> "Krb_cred"
  | `Enc_as_rep_part -> "Enc_as_rep_part"
  | `Enc_tgs_rep_part -> "Enc_tgs_rep_part"
  | `Enc_ap_rep_part -> "Enc_ap_rep_part"
  | `Enc_krb_priv_part -> "Enc_krb_priv_part"
  | `Enc_krb_cred_part -> "Enc_krb_cred_part"
  | `Krb_error -> "Krb_error"
