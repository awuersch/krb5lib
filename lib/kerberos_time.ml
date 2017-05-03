open Sexplib.Std
open Asn.S
open Krb_combinators

type t =
  { year : int
  ; month : int
  ; day : int
  ; hour : int
  ; minute : int
  ; second : int
  } [@@deriving sexp]

module Ast = struct
  type t = Ptime.t

  let asn = generalized_time
end

(* Per RFC 4120, all kerberos times are UTC, no fractional seconds. *)
let ast_of_t t =
  let date = t.year, t.month, t.day
  and time = (t.hour, t.minute, t.second), 0 in
  match Ptime.of_date_time (date, time) with
  | None -> failwith "invalid date or invalid time"
  | Some pt -> pt

(* Per RFC 4120, all kerberos times are UTC, no fractional seconds. *)
let t_of_ast pt =
  Ptime.to_date_time pt |> fun ((y, m, d), ((hh, mm, ss), _)) ->
  { year = y; month = m; day = d; hour = hh; minute = mm; second = ss }
