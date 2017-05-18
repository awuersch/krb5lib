type t = Kdc_req.t

module Ast = struct
  type t = Kdc_req.Ast.t
  let asn = Kdc_req.Ast.app_asn `Tgs_req
end

let ast_of_t t = Kdc_req.app_ast_of_t t `Tgs_req
let t_of_ast : Ast.t -> t = Kdc_req.t_of_ast
let sexp_of_t = Kdc_req.sexp_of_t
let t_of_sexp = Kdc_req.t_of_sexp
