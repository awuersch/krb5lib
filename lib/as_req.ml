open Sexplib.Std
open Kdc_req

type t =
  { padata : Pa_data.t list
  ; req_body : Kdc_req_body.t
  } [@@deriving sexp]

module Ast = struct
  type t = Kdc_req.Ast.t

  let asn = Application_tag.tag `As_req Kdc_req.Ast.asn
end

let ast_of_t t =
  Kdc_req.ast_of_t
    { Kdc_req.
      msg_type = `As_req
    ; padata = t.padata
    ; req_body = t.req_body
    }

let t_of_ast ast =
  Kdc_req.t_of_ast ast |> fun r ->
    if r.msg_type = `As_req then
      { padata = r.padata; req_body = r.req_body }
    else
      failwith (Printf.sprintf
        "wrong application tag %s" @@
        Application_tag.string_of_t r.msg_type)
