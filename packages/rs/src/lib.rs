use napi_derive::napi;
use sha2::{Digest, Sha256};
use base64::engine::general_purpose::STANDARD as base64_engine;
use base64::Engine;
use chrono::Utc;
use url::Url;
use std::collections::HashMap;
use rsa::{RsaPrivateKey, pkcs1::DecodeRsaPrivateKey, PaddingScheme, Hash};
use rsa::errors::Error;

#[napi(object)]
pub struct PrivateKey {
    pub private_key_pem: String,
    pub key_id: String,
}

#[napi(object)]
#[derive(Clone)]
pub struct Request {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
}

#[napi(object)]
pub struct SignedRequest {
    pub request: Request,
    pub signing_string: String,
    pub signature: String,
    pub signature_header: String,
}

#[napi]
pub fn create_signed_post(
    key: PrivateKey,
    url: String,
    body: String,
    additional_headers: HashMap<String, String>,
) -> SignedRequest {
    let u = Url::parse(&url).unwrap();
    let digest_header = format!("SHA-256={}", base64_engine.encode(Sha256::digest(body.as_bytes())));

    let mut headers = HashMap::new();
    headers.insert("Date".to_string(), Utc::now().to_rfc2822());
    headers.insert("Host".to_string(), u.host_str().unwrap().to_string());
    headers.insert("Content-Type".to_string(), "application/activity+json".to_string());
    headers.insert("Digest".to_string(), digest_header);
    headers.extend(additional_headers);

    let request = Request {
        url: u.to_string(),
        method: "POST".to_string(),
        headers,
    };

    match sign_to_request(&request, &key, vec!["(request-target)", "date", "host", "digest"]) {
        Ok((signing_string, signature, signature_header)) => {
            SignedRequest {
                request,
                signing_string,
                signature,
                signature_header,
            }
        }
        Err(e) => panic!("Failed to sign the request: {:?}", e),
    }
}


fn sign_to_request(request: &Request, key: &PrivateKey, include_headers: Vec<&str>) -> Result<(String, String, String), Error> {
	let signing_string = gen_signing_string(request, &include_headers);
	
	// PEMからRSA秘密鍵をデコード
	let private_key = RsaPrivateKey::from_pkcs1_pem(&key.private_key_pem)?;

	// 署名アルゴリズムとハッシュ関数の設定
	let padding = PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256));
	
	// 署名を生成
	let signature = private_key.sign(padding, signing_string.as_bytes())?;
	let encoded_signature = base64_engine.encode(signature);

	// 署名ヘッダーの生成
	let signature_header = format!(
			r#"keyId="{}",algorithm="rsa-sha256",headers="{}",signature="{}""#,
			key.key_id,
			include_headers.join(" "),
			encoded_signature
	);

	Ok((signing_string, encoded_signature, signature_header))
}

fn gen_signing_string(request: &Request, include_headers: &[&str]) -> String {
    let headers = lc_object_key(&request.headers);

    let mut results = Vec::new();

    for key in include_headers.iter().map(|x| x.to_lowercase()) {
        if key == "(request-target)" {
            results.push(format!("(request-target): {} {}", request.method.to_lowercase(), Url::parse(&request.url).unwrap().path()));
        } else {
            results.push(format!("{}: {}", key, headers.get(&key).unwrap()));
        }
    }

    results.join("\n")
}

fn lc_object_key(src: &HashMap<String, String>) -> HashMap<String, String> {
    let mut dst = HashMap::new();
    for (key, value) in src.iter() {
        dst.insert(key.to_lowercase(), value.clone());
    }
    dst
}

fn object_assign_with_lc_key(base: HashMap<String, String>, additional: HashMap<String, String>) -> HashMap<String, String> {
	let mut result = base.clone();
	for (key, value) in additional {
			result.insert(key.to_lowercase(), value);
	}
	result
}

#[napi]
pub fn create_signed_get(key: PrivateKey, url: String, additional_headers: HashMap<String, String>) -> SignedRequest {
	let u = Url::parse(&url).expect("Invalid URL");

	let mut base_headers = HashMap::new();
	base_headers.insert("Accept".to_string(), "application/activity+json, application/ld+json".to_string());
	base_headers.insert("Date".to_string(), Utc::now().to_rfc2822());
	base_headers.insert("Host".to_string(), u.host_str().unwrap().to_string());

	let headers = object_assign_with_lc_key(base_headers, additional_headers);

	let request = Request {
			url: u.to_string(),
			method: "GET".to_string(),
			headers,
	};

	match sign_to_request(&request, &key, vec!["(request-target)", "date", "host", "digest"]) {
		Ok((signing_string, signature, signature_header)) => {
				SignedRequest {
						request,
						signing_string,
						signature,
						signature_header,
				}
		}
		Err(e) => panic!("Failed to sign the request: {:?}", e),
	}
}
