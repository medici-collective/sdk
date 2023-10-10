// Copyright (C) 2019-2023 Aleo Systems Inc.
// This file is part of the Aleo SDK library.

// The Aleo SDK library is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// The Aleo SDK library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with the Aleo SDK library. If not, see <https://www.gnu.org/licenses/>.

use crate::{
    account::{Address, PrivateKey, Signature},
    types::{CurrentNetwork, ComputeKey, FieldNative, Field, FromBits, FromBytes, Group, Literal, Network, Scalar, SizeInDataBits, ToBytes, ToField, ToFields, U8, Value}
};

use anyhow::Error;
use rand::{rngs::StdRng, SeedableRng};
use wasm_bindgen::prelude::*;
use std::collections::HashMap;
use snarkvm_wasm::{Uniform, ToBits};
use itertools::Itertools;


#[wasm_bindgen]
pub struct JsField(FieldNative);




#[wasm_bindgen]
impl JsField {

    // gen_message(nonce, message_plaintext) → msg_Leo_verify: { field_1: 123125field, field_2:123131field },
    // msg_client_signing: ["field_1: 123125field, field_2:123131".to_fields()]
    pub fn generate_message_leo (
        private_key: &PrivateKey,
        message: &[u8],
        seed: &[u8],
    ) -> String {

        // {record} -> encode(record) -> generate_message
        // question what are we  are we sending in?
        // all we need is message verify to be the same as message sign
        // Ensure the number of field elements does not exceed the maximum allowed size.
        // Sample a random nonce from the scalar field.

        let seed_array = <[u8; 32]>::try_from(seed).expect("Invalid seed length");
        let mut rng = StdRng::from_seed(seed_array);

        let msg_bits: &[bool] = &message.to_bits_le();

        let message_fields: Vec<Field<CurrentNetwork>> =
            msg_bits.chunks(Field::<CurrentNetwork>::size_in_data_bits()).map(Field::from_bits_le).collect::<Result<Vec<_>, Error>>().unwrap();

        // let nonce: Scalar<CurrentNetwork> = Scalar::rand(&mut rng);

        // Compute `g_r` as `nonce * G`.
        // let g_r = Network::g_scalar_multiply(&nonce);

        // convert field to bytes
        // let bytes_to_field_elements = |bytes:&[u8]|
        // { bytes.iter().map(|byte| U8::new(*byte).to_field()).collect::<Result<Vec<_>, Error>>() }.unwrap();

        // let msg_fields = bytes_to_field_elements(message);
        // todo: GOAL: get it all under 1 roof...
        // todo: return string of signature
        // let value = Value::<CurrentNetwork>::from_bytes_le(message).unwrap();
        // let message_fields = value.to_fields().unwrap();

        let nonce = Scalar::rand(&mut rng);

        let g_r = Network::g_scalar_multiply(&nonce);

        let pk_sig = Network::g_scalar_multiply(&private_key.sk_sig());

        let pr_sig = Network::g_scalar_multiply(&private_key.r_sig());

        let compute_key = ComputeKey::try_from((pk_sig, pr_sig)).unwrap();

        let address = compute_key.to_address();

        let mut msg = Vec::with_capacity(4 + message_fields.len());
        msg.extend([g_r, pk_sig, pr_sig, *address].map(|point| point.to_x_coordinate()));
        msg.extend(message_fields);

        let mut my_dict: HashMap<String, Value<CurrentNetwork>> = HashMap::new();

        for (index, field) in msg.clone().into_iter().enumerate() {
            let lit = Literal::Field(field);
            let val = Value::from(&lit); // assuming the conversion takes a reference
            let key = format!("field_{}", index + 1);  // generate key in the format "field_i"
            my_dict.insert(key, val);
        }

        let string_representation: String = my_dict.iter()
        .map(|(k, v)| (k, k.trim_start_matches("field_").parse::<usize>().unwrap_or(0), v)) // extract numeric part
        .sorted_by(|(_, a_num, _), (_, b_num, _)| a_num.cmp(b_num)) // sort by the numeric part
        .map(|(key, _, value)| format!("  {}: {:?}", key, value)) // Use Debug trait for formatting
        .collect::<Vec<String>>()
        .join(",\n");

        let result = format!("{{\n{}\n}}", string_representation);

        // let val_of_dict: Value<CurrentNetwork> = Value::try_from(&result).unwrap();

        // let val_unwrapped = val_of_dict;

        // let mut res = val_unwrapped.to_fields().unwrap();

        // let first_four_message = msg[0..4].to_vec();

        // &res.splice(0..0, first_four_message);

        // let mut res_my_dict: HashMap<String, Value<CurrentNetwork>> = HashMap::new();

        // for (index, field) in res.clone().into_iter().enumerate() {
        //     let lit = Literal::Field(field);
        //     let val = Value::from(&lit); // assuming the conversion takes a reference
        //     let key = format!("field_{}", index + 1);  // generate key in the format "field_i"
        //     res_my_dict.insert(key, val);
        // }

        // let res_string_representation: String = res_my_dict.iter()
        //     .map(|(k, v)| (k, k.trim_start_matches("field_").parse::<usize>().unwrap_or(0), v)) // extract numeric part
        //     .sorted_by(|(_, a_num, _), (_, b_num, _)| a_num.cmp(b_num)) // sort by the numeric part
        //     .map(|(key, _, value)| format!("  {}: {:?}", key, value)) // Use Debug trait for formatting
        //     .collect::<Vec<String>>()
        //     .join(",\n");

        // let final_string = format!("{{\n{}\n}}", res_string_representation);

        return result;






        // yank in my_dict stuff ?

        // let bits: Vec<bool> = message.to_bits_le();

        // let msg_fields: Vec<Field<CurrentNetwork>> = bits
        // .chunks(Field::<CurrentNetwork>::size_in_data_bits())
        // .filter_map(|chunk| Field::<CurrentNetwork>::from_bits_le(chunk).ok())
        // .collect();
        // let msg_fields = Field::<CurrentNetwork>::from_bits_le(&message.to_bits_le());

        // derive the compute key directly from sk sig and r sig because tryfrom not impl for ck from pk
        // would have to bring in ck code into repo, below is a simpler way to do it for now
        let pk_sig = Network::g_scalar_multiply(&private_key.sk_sig());

        let pr_sig = Network::g_scalar_multiply(&private_key.r_sig());

        let compute_key = ComputeKey::try_from((pk_sig, pr_sig)).unwrap();

        // let msg_fields: Result<Vec<Field<CurrentNetwork>>, Error> = message.to_bits_le().chunks(Field::<CurrentNetwork>::size_in_data_bits()).map(Field::from_bits_le).collect::<Result<Vec<_>, Error>>();
        // Derive the compute key from the private key.
        // Retrieve pk_sig.
        let compute_pk_sig = compute_key.pk_sig();
        // Retrieve pr_sig.
        let compute_pr_sig = compute_key.pr_sig();

        // Derive the address from the compute key.
        // todo: make sure this address is the same as the one right below.
        let address = compute_key.to_address();
        // let address = Address::try_from(compute_key)?;

        // Construct the hash input as (r * G, pk_sig, pr_sig, address, message).
        // let mut msg = Vec::with_capacity(4 + msg_fields.len());
        // msg.extend([g_r, pk_sig, pr_sig, *address].map(|point| point.to_x_coordinate()));
        // msg.extend(&msg_fields);


        // let value = Value::<CurrentNetwork>::from_bytes_le(message).unwrap();
        // let msg_to_fields = value.to_fields().unwrap();
        // preimage.extend(msg_fields)

        // Insert dictionary and hash map logic here
        // let mut my_dict: HashMap<String, Field<CurrentNetwork>> = HashMap::new();

        // create hashmap of {field_1: 12413532341field, .....}
        // for (index, field) in msg.clone().into_iter().enumerate() {
        //     // let lit = Literal::Field(field);
        //     let val = field; // assuming the conversion takes a reference
        //     let key = format!("field_{}", index + 1);  // generate key in the format "field_i"
        //     my_dict.insert(key, val);
        // }

        // convert to string....
        // let string_representation: String = my_dict.iter()
        // .map(|(k, v)| (k, k.trim_start_matches("field_").parse::<usize>().unwrap_or(0), v)) // extract numeric part
        // .sorted_by(|(_, a_num, _), (_, b_num, _)| a_num.cmp(b_num)) // sort by the numeric part
        // .map(|(key, _, value)| format!("  {}: {:?}", key, value)) // Use Debug trait for formatting
        // .collect::<Vec<String>>()
        // .join(",\n");

        // let result = format!("{{\n{}\n}}", string_representation);

        // result


        // Result is a string and the Leo opcode for verify takes the message and turns it to field
        // It does this by figuring out the value is a plaintext
        // It then uses plaintext.to_field() which does the following
        // let mut bits_le = self.to_bits_le();
        // Adds one final bit to the data, to serve as a terminus indicator.
        // During decryption, this final bit ensures we've reached the end.
        // bits_le.push(true);
        //
        // let fields = bits_le
        // .chunks(Field::<N>::size_in_data_bits())
        // .map(Field::<N>::from_bits_le)
        // .collect::<Result<Vec<_>>>()?;
        // Then it has some logic to ensure the field elements don't exceed max size

        // need to convert string to bits
        // let val_of_dict: Vec<bool> = String::to_bits_le(&result);

        // let val_unwrapped = val_of_dict.unwrap(); // <-- don't need this anymore bc tryfrom is result; this isn't
        // need to convert bits to vec of fields
        // borrowed logic to chunk vec of bits_le to vec of field from above

        // let fields = match val_of_dict
        //     .chunks(Field::<CurrentNetwork>::size_in_data_bits())
        //     .map(Field::<CurrentNetwork>::from_bits_le)
        //     .collect::<Result<Vec<_>, _>>() {
        //     Ok(f) => f,
        //     Err(_) => {
        //         println!("error"); // Handle the error in some way
        //         return "Error".to_string();
        //     }
        // };

        // Keeping as res so don't have to change as much before
        // let mut res: Vec<Field<CurrentNetwork>> = fields;
        // let first_four_message = msg[0..4].to_vec();
        // &res.splice(0..0, first_four_message);

        // let res_string_representation: String = msg_fields.iter()
        //     .enumerate()
        //     .map(|(i, field)| format!("field_{}: {}", i + 1, field.to_string()))
        //     .collect::<Vec<_>>()
        //     .join("\n");

        // let final_string = format!("{{\n{}\n}}", res_string_representation);

        // final_string


        // println!("{:?}", res);

        // let mut message_bytes = Vec::new();

        // for field in &res {
        //     match field.to_bytes_le() {
        //         Ok(bytes) => message_bytes.extend_from_slice(&bytes),
        //         Err(e) => {
        //         }
        //     }
        // }

        // // convert to le bytes

        // let sig = Signature::sign_message(private_key, &message_bytes);

        // println!("{}", sig);

        // let fields_str = res.iter()
        //     .enumerate()
        //     .map(|(i, field)| format!("field_{}: {}", i + 1, field.to_string()))
        //     .collect::<Vec<_>>()
        //     .join(",\n  ");

        // println!("{:?}", res);

        // // test sign here and see if it works...

        // println!("{}", sig);

        // message_bytes
    }
}