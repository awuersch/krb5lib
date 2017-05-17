module type Intable = sig
  type t

  val t_of_int : int -> t
  val int_of_t : t -> int
  val t_of_string : string -> t
  val string_of_t : t -> string
end

module OrderedType_of_Intable (M : Intable) = struct
  type t = M.t

  let compare t t' = compare (M.int_of_t t) (M.int_of_t t')
end

module type ALIST = sig
  type t
  val alist : (t * int * string) list
end

(* Slower than a custom Intable implementation *)
module Intable_of_alist (M : ALIST) : Intable with type t = M.t = struct
  type t = M.t

  let t_of_int n =
    let l = M.alist in
    let p = try List.find (fun (_, n', _) -> n = n') l with
      (* convert out of range values to random in range values *)
      Not_found -> List.length l |> Random.int |> List.nth l
    in
      let (t, _, _) = p in t

  let int_of_t t =
    let l = M.alist in
    let p = try List.find (fun (t', _, _) -> t = t') l with
      (* convert out of range values to random in range values *)
      Not_found -> List.length l |> Random.int |> List.nth l
    in
      let (_, i, _) = p in i

  let t_of_string s =
    let l = M.alist in
    let p = try List.find (fun (_, _, s') -> s = s') l with
      (* convert out of range values to random in range values *)
      Not_found -> List.length l |> Random.int |> List.nth l
    in
      let (t, _, _) = p in t

  let string_of_t t =
    let l = M.alist in
    let p = try List.find (fun (t', _, _) -> t = t') l with
      (* convert out of range values to random in range values *)
      Not_found -> List.length l |> Random.int |> List.nth l
    in
      let (_, _, s) = p in s
end
