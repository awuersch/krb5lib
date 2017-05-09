module type Intable = sig
  type t

  val t_of_int : int -> t
  val int_of_t : t -> int
end

module OrderedType_of_Intable (M : Intable) = struct
  type t = M.t

  let compare t t' = compare (M.int_of_t t) (M.int_of_t t')
end

module type ALIST = sig
  type t
  val alist : (t * int) list
end

(* Slower than a custom Intable implementation *)
module Intable_of_alist (M : ALIST) : Intable with type t = M.t = struct
  type t = M.t

  let t_of_int n =
    let l = M.alist in
    let p = try List.find (fun (_, n') -> n = n') l with
      (* convert out of range values to random in range values *)
      Not_found -> List.length l |> Random.int |> List.nth l
    in
      fst p

  let int_of_t t =
    let l = M.alist in
    let p = try List.find (fun (t', _) -> t = t') l with
      (* convert out of range values to random in range values *)
      Not_found -> List.length l |> Random.int |> List.nth l
    in
      snd p
end
