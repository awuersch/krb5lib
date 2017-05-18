type t = Enc_kdc_rep_part.t

module Ast = struct
  type t = Enc_kdc_rep_part.Ast.t
  let asn = Enc_kdc_rep_part.Ast.app_asn `Enc_as_rep_part
end

let ast_of_t = Enc_kdc_rep_part.ast_of_t
let t_of_ast = Enc_kdc_rep_part.t_of_ast
let sexp_of_t = Enc_kdc_rep_part.sexp_of_t
let t_of_sexp = Enc_kdc_rep_part.t_of_sexp
