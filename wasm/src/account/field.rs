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
    account::PrivateKey,
    native::{CurrentNetwork, ComputeKey, FieldNative, Field, FromBits, Literal, Network, Scalar, SizeInDataBits, ToFields, Value}
};

use anyhow::Error;
use rand::{rngs::StdRng, SeedableRng};
use snarkvm_console::program::Itertools;
use wasm_bindgen::prelude::*;
use std::collections::HashMap;
use snarkvm_wasm::utilities::{Uniform, ToBits};


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

        let vec_msg_first_field = vec![message_fields[0]];

        let nonce = Scalar::rand(&mut rng);

        let g_r = Network::g_scalar_multiply(&nonce);

        let pk_sig = Network::g_scalar_multiply(&private_key.sk_sig());

        let pr_sig = Network::g_scalar_multiply(&private_key.r_sig());

        let compute_key = ComputeKey::try_from((pk_sig, pr_sig)).unwrap();

        let address = compute_key.to_address();

        let mut msg = Vec::with_capacity(4 + message_fields.len());
        msg.extend([g_r, pk_sig, pr_sig, *address].map(|point| point.to_x_coordinate()));
        msg.extend(vec_msg_first_field);

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
        .map(|(key, _, value)| format!("{}: {:?}", key, value)) // Use Debug trait for formatting
        .collect::<Vec<String>>()
        .join(",\n");

        let result = format!("{{\n{}\n}}", string_representation);

        return result;

    }


    pub fn generate_message_clients (
        private_key: &PrivateKey,
        message: &[u8],
        seed: &[u8]
    ) -> String {

        let seed_array = <[u8; 32]>::try_from(seed).expect("Invalid seed length");
        let mut rng = StdRng::from_seed(seed_array);

        let msg_bits: &[bool] = &message.to_bits_le();

        let message_fields: Vec<Field<CurrentNetwork>> =
            msg_bits.chunks(Field::<CurrentNetwork>::size_in_data_bits()).map(Field::from_bits_le).collect::<Result<Vec<_>, Error>>().unwrap();

        let vec_msg_first_field = vec![message_fields[0]];

        let nonce = Scalar::rand(&mut rng);

        let g_r = Network::g_scalar_multiply(&nonce);

        let pk_sig = Network::g_scalar_multiply(&private_key.sk_sig());

        let pr_sig = Network::g_scalar_multiply(&private_key.r_sig());

        let compute_key = ComputeKey::try_from((pk_sig, pr_sig)).unwrap();

        let address = compute_key.to_address();

        let mut msg = Vec::with_capacity(4 + message_fields.len());
        msg.extend([g_r, pk_sig, pr_sig, *address].map(|point| point.to_x_coordinate()));
        msg.extend(vec_msg_first_field);

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
        .map(|(key, _, value)| format!("{}: {:?}", key, value)) // Use Debug trait for formatting
        .collect::<Vec<String>>()
        .join(",\n");

        let result = format!("{{\n{}\n}}", string_representation);

        let val_of_dict: Value<CurrentNetwork> = Value::try_from(&result).unwrap();

        let val_unwrapped = val_of_dict;

        let msg_to_fields = val_unwrapped.to_fields().unwrap();

        let mut dict_of_fields: HashMap<String, Value<CurrentNetwork>> = HashMap::new();

        for (index, field) in msg_to_fields.clone().into_iter().enumerate() {
            let lit = Literal::Field(field);
            let val = Value::from(&lit); // assuming the conversion takes a reference
            let key = format!("field_{}", index + 1);  // generate key in the format "field_i"
            dict_of_fields.insert(key, val);
        }

        let fields_string_representation: String = dict_of_fields.iter()
        .map(|(k, v)| (k, k.trim_start_matches("field_").parse::<usize>().unwrap_or(0), v)) // extract numeric part
        .sorted_by(|(_, a_num, _), (_, b_num, _)| a_num.cmp(b_num)) // sort by the numeric part
        .map(|(key, _, value)| format!("  {}: {:?}", key, value)) // Use Debug trait for formatting
        .collect::<Vec<String>>()
        .join(",\n");

        let msg_to_fields_str = format!("{{\n{}\n}}", fields_string_representation);

        return msg_to_fields_str;

    }
}