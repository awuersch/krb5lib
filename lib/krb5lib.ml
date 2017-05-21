(*---------------------------------------------------------------------------
   Copyright (c) 2017 Tony Wuersch. All rights reserved.
   Copyright (c) 2015 Brandon Bohrer. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
   %%NAME%% %%VERSION%%
  ---------------------------------------------------------------------------*)

module Msg = struct 

  module Interfaces = Interfaces

  module Asn1_intf = Asn1_intf

  module Krb_int32 = Krb_int32

  module Microseconds = Microseconds

  module Uint32 = Uint32

  module Kerberos_string = Kerberos_string

  module Octet_string = Octet_string

  module Kerberos_time = Kerberos_time

  module Address_type = Address_type

  module Ap_options = Ap_options

  module Ap_req = Ap_req

  module Ap_rep = Ap_rep

  module Application_tag = Application_tag

  module As_req = As_req

  module As_rep = As_rep

  module Authenticator = Authenticator

  module Authorization_data = Authorization_data

  module Encrypted_data = Encrypted_data

  module Encryption_key = Encryption_key

  module Encryption_type = Encryption_type

  module Checksum_type = Checksum_type

  module Checksum = Checksum

  module Enc_kdc_rep_part = Enc_kdc_rep_part

  module Enc_ap_rep_part = Enc_ap_rep_part

  module Enc_as_rep_part = Enc_as_rep_part

  module Enc_krb_cred_part = Enc_krb_cred_part

  module Enc_krb_priv_part = Enc_krb_priv_part

  module Enc_tgs_rep_part = Enc_tgs_rep_part

  module Enc_ticket_part = Enc_ticket_part

  module Fast_armor_type = Fast_armor_type

  module Fast_options = Fast_options

  module Host_addresses = Host_addresses

  module Host_address = Host_address

  module Kdc_rep = Kdc_rep

  module Kdc_req_body = Kdc_req_body

  module Kdc_req = Kdc_req

  module Kdc_options = Kdc_options

  module Krb_cred = Krb_cred

  module Krb_cred_info = Krb_cred_info

  module Krb_error = Krb_error

  module Krb_priv = Krb_priv

  module Krb_safe_body = Krb_safe_body

  module Krb_safe = Krb_safe

  module Last_req_inst = Last_req_inst

  module Last_req = Last_req

  module Name_type = Name_type

  module Pa_data_type = Pa_data_type

  module Pa_data = Pa_data

  module Principal_name = Principal_name

  module Realm = Realm

  module Tcp_extension = Tcp_extension

  module Tgs_rep = Tgs_rep

  module Tgs_req = Tgs_req

  module Ticket_flags = Ticket_flags

  module Ticket = Ticket

  module Transited_encoding = Transited_encoding

  module Transport_type = Transport_type

  module Types = Types
end

(*---------------------------------------------------------------------------
   Copyright (c) 2017 Tony Wuersch
   Copyright (c) 2015 Brandon Bohrer

   Permission to use, copy, modify, and/or distribute this software for any
   purpose with or without fee is hereby granted, provided that the above
   copyright notice and this permission notice appear in all copies.

   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
  ---------------------------------------------------------------------------*)
