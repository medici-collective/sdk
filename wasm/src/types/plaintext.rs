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

use crate::types::native::PlaintextNative;
use crate::native::Network;
use crate::network_string_id;
use snarkvm_console::network::TestnetV0;
use snarkvm_console::prelude::ToBits;

use wasm_bindgen::prelude::wasm_bindgen;

use std::str::FromStr;


#[wasm_bindgen]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Plaintext{
  network: String,
  as_string: String
}

#[wasm_bindgen]
impl Plaintext {
    #[wasm_bindgen(js_name = "toString")]
    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
      self.as_string.clone()
    }

    #[wasm_bindgen(js_name = "fromString")]
    pub fn from_string(plaintext: &str) -> Result<Plaintext, String> {
      match plaintext_from_string_impl(plaintext) {
        Ok(result) => Ok(Self{ network: "TestnetV0".to_string(), as_string: result}),
        Err(e) => return Err(e)
      }
    }

    #[wasm_bindgen(js_name = "hashBhp256")]
    pub fn hash_bhp256(&self) -> Result<String, String> {
      match plaintext_hash_bhp256_impl::<TestnetV0>(&self.as_string) {
        Ok(result) => Ok(result),
        Err(e) => return Err(e)
      }
    }
}

pub fn plaintext_from_string_impl(plaintext: &str) -> Result<String, String> {
  let plaintext_string = PlaintextNative::from_str(plaintext).map_err(|e| e.to_string())?.to_string();
  Ok(plaintext_string)
}

pub fn plaintext_hash_bhp256_impl<N: Network>(plaintext_string: &str) -> Result<String, String> {
  let literal = PlaintextNative::from_str(&plaintext_string).unwrap();
  let bits = literal.to_bits_le();
  let field_string = N::hash_bhp256(&bits).map_err(|e| e.to_string())?.to_string();
  Ok(field_string)
}

impl From<PlaintextNative> for Plaintext {
    fn from(native: PlaintextNative) -> Self {
      let network = network_string_id!(TestnetV0::ID).unwrap().to_string();
      Self { network, as_string: native.to_string() }
    }
}

impl From<Plaintext> for PlaintextNative {
    fn from(plaintext: Plaintext) -> Self {
      PlaintextNative::from_str(&plaintext.as_string).unwrap()
    }
}


// Write tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plaintext_to_bytes() {
      let plaintext_string = "{ account: aleo15xd9tee983ts3urff8j22q64wvcyc8geakghyc3ew5u0v8jfuqgs958t6d, token_id: 4846247369341682005field }";
      let plaintext = Plaintext::from_string( &plaintext_string).unwrap();

      let hash = plaintext.hash_bhp256().unwrap();
      assert_eq!(hash, "5516020691424619214358523651321345610671348418282339232497640613253889639415field");
    }
}