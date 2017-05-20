type t = Kdc_rep.t

module Ast = struct
  type t = Kdc_rep.Ast.t
  let asn = Application_tag.tag `Tgs_rep Kdc_rep.Ast.asn
end

let ast_of_t = Kdc_rep.app_ast_of_t `Tgs_rep
let t_of_ast : Ast.t -> t = Kdc_rep.t_of_ast
let sexp_of_t = Kdc_rep.sexp_of_t
let t_of_sexp = Kdc_rep.t_of_sexp
