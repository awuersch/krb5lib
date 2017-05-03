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
    fst (List.find (fun (_, n') -> n = n') M.alist)

  let int_of_t t =
    snd (List.find (fun (t', _) -> t = t') M.alist)

end
