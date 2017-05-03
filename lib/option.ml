type 'a t = 'a option

let return x = Some x

let bind ~f x =
  match x with
  | None -> None
  | Some x -> f x

let map ~f x = bind x ~f:(fun x -> return (f x))
