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
    account::{Address, PrivateKey},
    types::{CurrentNetwork, ComputeKey, Network, Scalar, SignatureNative, ToFields, Value}
};
use snarkvm_wasm::{Uniform};
// use std::collections::HashMap;
// use itertools::Itertools;

use core::{fmt, ops::Deref, str::FromStr};
use rand::{rngs::StdRng, SeedableRng};
use wasm_bindgen::prelude::*;

/// Cryptographic signature of a message signed by an Aleo account
#[wasm_bindgen]
pub struct Signature(SignatureNative);

#[wasm_bindgen]
impl Signature {
    /// Sign a message with a private key
    ///
    /// @param {PrivateKey} private_key The private key to sign the message with
    /// @param {Uint8Array} message Byte representation of the message to sign
    /// @returns {Signature} Signature of the message
    pub fn sign(private_key: &PrivateKey, message: &[u8]) -> Self {
        Self(SignatureNative::sign_bytes(private_key, message, &mut StdRng::from_entropy()).unwrap())
    }


    pub fn sign_message(private_key: &PrivateKey, message: &[u8], seed: &[u8]) -> Self {

        // if message.len() > N::MAX_DATA_SIZE_IN_FIELDS as usize {
        //     bail!("Cannot sign the message: the message exceeds maximum allowed size")
        // }

        let seed_array = <[u8; 32]>::try_from(seed).expect("Invalid seed length");

        let mut rng = StdRng::from_seed(seed_array);

        let slice: &[u8] = &message; // your data here
        let result_string = match std::str::from_utf8(slice) {
            Ok(v) => v.to_string(),
            Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
        };

        let value: Value<CurrentNetwork> = Value::from_str(&result_string).unwrap();

        let mut message = value.to_fields().unwrap();

        let nonce = Scalar::rand(&mut rng);

        let g_r = Network::g_scalar_multiply(&nonce);

        let pk_sig = Network::g_scalar_multiply(&private_key.sk_sig());

        let pr_sig = Network::g_scalar_multiply(&private_key.r_sig());

        let compute_key = ComputeKey::try_from((pk_sig, pr_sig)).unwrap();

        let address = compute_key.to_address();


        // need to splice in g_r, pk_sig, pr_sig, address ... and sign against that
        let prepend_items: Vec<_> = [g_r, pk_sig, pr_sig, *address]
        .iter() // Convert the array to an iterator
        .map(|&point| point.to_x_coordinate())
        .collect();

        message.splice(0..0, prepend_items);

        // Compute the verifier challenge.
        let challenge = Network::hash_to_scalar_psd8(&message).unwrap();

        // Compute the prover response.
        let response = nonce - (challenge * private_key.sk_sig());

        // Ok(Self { challenge, response, compute_key })

        let sig = SignatureNative::from((challenge, response, compute_key));


        // note: keeping result, dict, etc below here for debugging message that one is signing against.
        // to see message one is signing against, change return to string and return result
        // let result = format!("{{\n{}\n}} + {}", string_representation, sig);

        // let mut my_dict: HashMap<String, Value<CurrentNetwork>> = HashMap::new();

        // for (index, field) in message.clone().into_iter().enumerate() {
        //     let lit = Literal::Field(field);
        //     let val = Value::from(&lit); // assuming the conversion takes a reference
        //     let key = format!("field_{}", index + 1);  // generate key in the format "field_i"
        //     my_dict.insert(key, val);
        // }


        // Output the signature.
        // let string_representation: String = my_dict.iter()
        // .map(|(k, v)| (k, k.trim_start_matches("field_").parse::<usize>().unwrap_or(0), v)) // extract numeric part
        // .sorted_by(|(_, a_num, _), (_, b_num, _)| a_num.cmp(b_num)) // sort by the numeric part
        // .map(|(key, _, value)| format!("  {}: {:?}", key, value)) // Use Debug trait for formatting
        // .collect::<Vec<String>>()
        // .join(",\n");

        Self(sig)
    }
    // Verify the signature.
    // let address = Address::try_from(&private_key).unwrap();
    // assert!(signature.verify(&address, &message));

    // // Print the results.
    // print!("{signature}");
    // print!(" {address}");
    // print!(" \"{value}\"")

    /// Ignore the mess below -- me testing things
    // let message_in_bits = message.to_bits_le();
    // println!("message in bits is {:?}", message_in_bits);
    // let message_in_field = message_in_bits.chunks(Field::<N>::size_in_data_bits()).map(Field::from_bits_le).collect::<Result<Vec<_>>>()?;
    // println!("message in field is {:?}", message_in_field);


    /// Turn a message into bits
    ///
    /// @param {Uint8Array} message Byte representation of the message to sign
    /// @returns {Vec<bool>} Vec of bool of the message
    // pub fn gen_bits_message(message: &[u8]) -> Vec<bool> {
    //     (message.to_bits_le()).to_string()
    // }

    /// Verify a signature of a message with an address
    ///
    /// @param {Address} address The address to verify the signature with
    /// @param {Uint8Array} message Byte representation of the message to verify
    /// @returns {boolean} True if the signature is valid, false otherwise
    pub fn verify(&self, address: &Address, message: &[u8]) -> bool {
        self.0.verify_bytes(address, message)
    }

    /// Get a signature from a string representation of a signature
    ///
    /// @param {string} signature String representation of a signature
    /// @returns {Signature} Signature
    pub fn from_string(signature: &str) -> Self {
        Self::from_str(signature).unwrap()
    }

    /// Get a string representation of a signature
    ///
    /// @returns {string} String representation of a signature
    #[allow(clippy::inherent_to_string_shadow_display)]
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }
}

impl FromStr for Signature {
    type Err = anyhow::Error;

    fn from_str(signature: &str) -> Result<Self, Self::Err> {
        Ok(Self(SignatureNative::from_str(signature).unwrap()))
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Deref for Signature {
    type Target = SignatureNative;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{rngs::StdRng, Rng, SeedableRng};
    use wasm_bindgen_test::*;

    const ITERATIONS: u64 = 1_000;

    #[wasm_bindgen_test]
    pub fn test_sign_and_verify() {
        for _ in 0..ITERATIONS {
            // Sample a new private key and message.
            let private_key = PrivateKey::new();
            let message: [u8; 32] = StdRng::from_entropy().gen();

            // Sign the message.
            let signature = Signature::sign(&private_key, &message);
            // Check the signature is valid.
            assert!(signature.verify(&private_key.to_address(), &message));

            // Sample a different message.
            let bad_message: [u8; 32] = StdRng::from_entropy().gen();
            // Check the signature is invalid.
            assert!(!signature.verify(&private_key.to_address(), &bad_message));
        }
    }
}
