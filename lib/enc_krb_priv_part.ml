type t = Krb_safe_body.t

module Ast = struct
  type t = Krb_safe_body.Ast.t
  let asn = Application_tag.tag `Enc_krb_priv_part Krb_safe_body.Ast.asn
end

let ast_of_t = Krb_safe_body.ast_of_t
let t_of_ast = Krb_safe_body.t_of_ast
let sexp_of_t = Krb_safe_body.sexp_of_t
let t_of_sexp = Krb_safe_body.t_of_sexp
