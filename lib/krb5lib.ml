(*---------------------------------------------------------------------------
   Copyright (c) 2017 Tony Wuersch. All rights reserved.
   Copyright (c) 2015 Brandon Bohrer. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
   %%NAME%% %%VERSION%%
  ---------------------------------------------------------------------------*)

module Msg = struct 

  module Interfaces = Interfaces

  module type FLAG_TYPE = sig
    type t
  
    module Intable : Interfaces.Intable with type t = t
    module OrderedType : Set.OrderedType with type t = t
  
    module Encoding_options : sig
      (* Minimum number of bits to use when serializing a flag set *)
      val min_bits : int
    end
  end

  module Asn1_intf = Asn1_intf

  module Krb_int32 = Krb_int32

  module Uint32 = Uint32

  module Kerberos_string = Kerberos_string

  module Octet_string = Octet_string

  module Kerberos_time = Kerberos_time

  module Address_type = Address_type

  module Application_tag = Application_tag

  module As_req = As_req

  module Authorization_data = Authorization_data

  module Encrypted_data = Encrypted_data

  module Encryption_key = Encryption_key

  module Encryption_type = Encryption_type

  module Enc_ticket_part = Enc_ticket_part

  module Host_addresses = Host_addresses

  module Host_address = Host_address

  module Kdc_req_body = Kdc_req_body

  module Kdc_req = Kdc_req

  module Name_type = Name_type

  module Pa_data = Pa_data

  module Principal_name = Principal_name

  module Realm = Realm

  module Ticket_flags = Ticket_flags

  module Kdc_options = Kdc_options

  module Ticket = Ticket

  module Transited_encoding = Transited_encoding

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
