use axum::{
    extract::{Query, State},
    http::{header, HeaderValue, Method, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, warn};

type HmacSha256 = Hmac<Sha256>;

const SECRET_KEY: &str = "ece5b7b9c637456c135dfe87f571bc5e757f5e4e51e24306c8917a69d8540206";
const MAX_NUMBER: u32 = 50000;
const COOKIE_NAME: &str = "altcha_verified";

#[derive(Clone)]
struct AppState {
    secret_key: String,
}

#[derive(Serialize)]
struct Challenge {
    algorithm: String,
    challenge: String,
    maxnumber: u32,
    salt: String,
    signature: String,
}

#[derive(Deserialize)]
struct VerifyRequest {
    altcha: String,
}

#[derive(Deserialize)]
struct AltchaPayload {
    #[allow(dead_code)]
    algorithm: String,
    challenge: String,
    number: u32,
    salt: String,
    signature: String,
}

#[derive(Deserialize)]
struct ChallengePageQuery {
    return_to: Option<String>,
}

fn generate_salt() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.gen();
    hex::encode(bytes)
}

fn generate_challenge(
    salt: &str,
    _secret_key: &str,
) -> Result<(String, u32), Box<dyn std::error::Error>> {
    // ALTCHA proof-of-work: generate a secret number and create challenge from it
    let mut rng = rand::thread_rng();
    let secret_number: u32 = rng.gen_range(0..MAX_NUMBER);

    // Create challenge by hashing salt + secret_number
    let work_data = format!("{}{}", salt, secret_number);
    let mut hasher = Sha256::new();
    hasher.update(work_data.as_bytes());
    let hash = hasher.finalize();
    let challenge = hex::encode(hash);

    Ok((challenge, secret_number))
}

fn sign_challenge(
    challenge: &str,
    salt: &str,
    secret_key: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut mac = HmacSha256::new_from_slice(secret_key.as_bytes())?;
    mac.update(format!("{}{}", challenge, salt).as_bytes());
    let result = mac.finalize();
    Ok(hex::encode(result.into_bytes()))
}

fn create_verification_token(
    client_ip: &str,
    domain: &str,
    secret_key: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let expires = timestamp + 86400; // 24 hours

    // Create payload: ip|domain|expires
    let payload = format!("{}|{}|{}", client_ip, domain, expires);

    // Sign the payload
    let mut mac = HmacSha256::new_from_slice(secret_key.as_bytes())?;
    mac.update(payload.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    // Create token: base64(payload):signature
    let token = format!(
        "{}:{}",
        general_purpose::STANDARD.encode(payload.as_bytes()),
        signature
    );

    Ok(token)
}

fn verify_token(
    token: &str,
    client_ip: &str,
    domain: &str,
    secret_key: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let parts: Vec<&str> = token.split(':').collect();
    if parts.len() != 2 {
        return Ok(false);
    }

    let payload_b64 = parts[0];
    let provided_signature = parts[1];

    // Decode payload
    let payload_bytes = general_purpose::STANDARD.decode(payload_b64)?;
    let payload = String::from_utf8(payload_bytes)?;

    // Verify signature
    let mut mac = HmacSha256::new_from_slice(secret_key.as_bytes())?;
    mac.update(payload.as_bytes());
    let expected_signature = hex::encode(mac.finalize().into_bytes());

    if provided_signature != expected_signature {
        warn!("Invalid token signature from {}", client_ip);
        return Ok(false);
    }

    // Parse payload: ip|domain|expires
    let payload_parts: Vec<&str> = payload.split('|').collect();
    if payload_parts.len() != 3 {
        return Ok(false);
    }

    let token_ip = payload_parts[0];
    let token_domain = payload_parts[1];
    let expires: u64 = payload_parts[2].parse()?;

    // Check expiration
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if now > expires {
        info!("Expired token from {}", client_ip);
        return Ok(false);
    }

    // Check IP and domain match
    if token_ip != client_ip || token_domain != domain {
        warn!(
            "Token IP/domain mismatch: token={}@{}, actual={}@{}",
            token_ip, token_domain, client_ip, domain
        );
        return Ok(false);
    }

    Ok(true)
}

fn verify_solution(
    payload: &AltchaPayload,
    secret_key: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    // Verify signature
    let expected_signature = sign_challenge(&payload.challenge, &payload.salt, secret_key)?;
    if payload.signature != expected_signature {
        warn!(
            "Signature mismatch. Expected: {}, Got: {}",
            expected_signature, payload.signature
        );
        return Ok(false);
    }

    // Verify proof of work - hash must EQUAL the challenge (not start with)
    let work_data = format!("{}{}", payload.salt, payload.number);
    let mut hasher = Sha256::new();
    hasher.update(work_data.as_bytes());
    let hash = hasher.finalize();
    let hash_hex = hex::encode(hash);

    // Check if hash exactly matches challenge
    let challenge_met = hash_hex == payload.challenge;

    info!(
        "Verifying: salt={}, number={}, hash={}, challenge={}, matches={}",
        payload.salt,
        payload.number,
        &hash_hex[..8],
        &payload.challenge[..8],
        challenge_met
    );

    if !challenge_met {
        warn!(
            "Proof of work failed. Hash: {}, Challenge: {}",
            &hash_hex[..8],
            &payload.challenge[..8]
        );
        return Ok(false);
    }

    info!("ALTCHA verification successful. Hash matches challenge exactly");
    Ok(true)
}

fn get_host_domain(headers: &axum::http::HeaderMap) -> String {
    if let Some(host) = headers.get("host") {
        if let Ok(host_str) = host.to_str() {
            // Remove port if present
            let host_without_port = host_str.split(':').next().unwrap_or(host_str);
            return host_without_port.to_string();
        }
    }
    "localhost".to_string()
}

fn get_client_ip(headers: &axum::http::HeaderMap) -> String {
    // Check X-Forwarded-For header first (from nginx)
    if let Some(xff) = headers.get("x-forwarded-for") {
        if let Ok(xff_str) = xff.to_str() {
            if let Some(first_ip) = xff_str.split(',').next() {
                return first_ip.trim().to_string();
            }
        }
    }

    // Check X-Real-IP header
    if let Some(xri) = headers.get("x-real-ip") {
        if let Ok(xri_str) = xri.to_str() {
            return xri_str.to_string();
        }
    }

    // Fallback
    "unknown".to_string()
}

async fn challenge_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Challenge>, StatusCode> {
    info!("Challenge endpoint called");

    let salt = generate_salt();
    let (challenge, secret_number) = match generate_challenge(&salt, &state.secret_key) {
        Ok(result) => result,
        Err(e) => {
            warn!("Failed to generate challenge: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    match sign_challenge(&challenge, &salt, &state.secret_key) {
        Ok(signature) => {
            let response = Challenge {
                algorithm: "SHA-256".to_string(),
                challenge: challenge.clone(),
                maxnumber: MAX_NUMBER,
                salt: salt.clone(),
                signature: signature.clone(),
            };

            // Debug the response
            info!(
                "Generated challenge response: algorithm={}, challenge={}, maxnumber={}, salt={}, signature={}, secret_number={}",
                response.algorithm,
                &response.challenge[..8],
                response.maxnumber,
                response.salt,
                &response.signature[..8],
                secret_number
            );

            Ok(Json(response))
        }
        Err(e) => {
            warn!("Failed to generate challenge signature: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn verify_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<VerifyRequest>,
) -> Result<Response, StatusCode> {
    let client_ip = get_client_ip(&headers);
    let host_domain = get_host_domain(&headers);
    info!(
        "Verification attempt from IP: {} for domain: {}",
        client_ip, host_domain
    );

    // Decode base64 payload
    let payload_bytes = match general_purpose::STANDARD.decode(&req.altcha) {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!("Invalid base64 from {}: {}", client_ip, e);
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    // Parse JSON payload
    let payload: AltchaPayload = match serde_json::from_slice(&payload_bytes) {
        Ok(p) => p,
        Err(e) => {
            warn!("Invalid JSON payload from {}: {}", client_ip, e);
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    // Verify the solution
    match verify_solution(&payload, &state.secret_key) {
        Ok(true) => {
            info!(
                "ALTCHA verification successful for IP: {} on domain: {}",
                client_ip, host_domain
            );

            // Create signed verification token
            let token = match create_verification_token(&client_ip, &host_domain, &state.secret_key)
            {
                Ok(t) => t,
                Err(e) => {
                    warn!("Failed to create verification token: {}", e);
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
            };

            // Create verification cookie with signed token
            let cookie_value = format!(
                "{}={}; Path=/; Domain={}; HttpOnly; Secure; SameSite=Strict; Max-Age=86400",
                COOKIE_NAME, token, host_domain
            );

            let mut response = Json(serde_json::json!({
                "status": "verified",
                "message": "Verification successful"
            }))
            .into_response();

            response.headers_mut().insert(
                header::SET_COOKIE,
                HeaderValue::from_str(&cookie_value).unwrap(),
            );

            Ok(response)
        }
        Ok(false) => {
            warn!(
                "ALTCHA verification failed for IP: {} on domain: {}",
                client_ip, host_domain
            );
            Err(StatusCode::BAD_REQUEST)
        }
        Err(e) => {
            warn!(
                "Error verifying solution from {} on domain {}: {}",
                client_ip, host_domain, e
            );
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn validate_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<StatusCode, StatusCode> {
    let client_ip = get_client_ip(&headers);
    let host_domain = get_host_domain(&headers);

    // Get token from cookie
    let token = if let Some(cookie_header) = headers.get("cookie") {
        if let Ok(cookie_str) = cookie_header.to_str() {
            // Parse cookies to find altcha_verified
            let mut found_token = None;
            for cookie in cookie_str.split(';') {
                let cookie = cookie.trim();
                if let Some(value) = cookie.strip_prefix(&format!("{}=", COOKIE_NAME)) {
                    found_token = Some(value.to_string());
                    break;
                }
            }
            match found_token {
                Some(token) => token,
                None => {
                    info!("No {} cookie found from {}", COOKIE_NAME, client_ip);
                    return Err(StatusCode::UNAUTHORIZED);
                }
            }
        } else {
            warn!("Invalid cookie header from {}", client_ip);
            return Err(StatusCode::UNAUTHORIZED);
        }
    } else {
        info!("No cookie header from {}", client_ip);
        return Err(StatusCode::UNAUTHORIZED);
    };

    // Validate the token
    match verify_token(&token, &client_ip, &host_domain, &state.secret_key) {
        Ok(true) => {
            info!(
                "Valid token for IP: {} on domain: {}",
                client_ip, host_domain
            );
            Ok(StatusCode::OK)
        }
        Ok(false) => {
            warn!(
                "Invalid token from IP: {} on domain: {}",
                client_ip, host_domain
            );
            Err(StatusCode::UNAUTHORIZED)
        }
        Err(e) => {
            warn!("Token validation error for {}: {}", client_ip, e);
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

async fn challenge_page_handler(
    headers: axum::http::HeaderMap,
    Query(params): Query<ChallengePageQuery>,
) -> Html<String> {
    let host = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");

    let return_to = params
        .return_to
        .unwrap_or_else(|| format!("https://{}/", host));

    let html = format!(
        r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Verification Required - Princeton University Library</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script type="module" src="https://cdn.jsdelivr.net/npm/altcha@latest/dist/altcha.min.js"></script>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
            line-height: 1.6;
        }}
        .container {{
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
            margin-top: 50px;
        }}
        .logo {{
            color: #e87722;
            margin-bottom: 30px;
            font-size: 2em;
        }}
        h2 {{ color: #333; margin-bottom: 10px; }}
        p {{ color: #666; margin-bottom: 30px; }}
        altcha-widget {{
            margin: 20px 0;
            display: block;
        }}
        button {{
            background: #e87722;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            margin-top: 15px;
            min-width: 200px;
            transition: background-color 0.2s;
        }}
        button:hover:not(:disabled) {{ background: #d66a1a; }}
        button:disabled {{ background: #ccc; cursor: not-allowed; }}
        .info {{
            color: #666;
            font-size: 14px;
            margin-top: 20px;
            padding: 15px;
            background: #f9f9f9;
            border-radius: 4px;
        }}
        .loading {{
            color: #666;
            margin: 20px 0;
            font-style: italic;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            🎓 Princeton University Library
        </div>
        <h2>Security Verification Required</h2>
        <p>Please complete the verification below to continue to <strong>{}</strong></p>

        <div class="loading" id="loading">Loading verification challenge...</div>

        <form id="challenge-form" style="display: none;">
            <altcha-widget
                challengeurl="/api/challenge"
                spamfilter="false">
            </altcha-widget>
            <br>
            <button type="submit" id="submit-btn" disabled>Continue to Site</button>
        </form>

        <div class="info">
            This verification helps protect Princeton University Library resources from automated abuse.
            <br><small>Powered by ALTCHA - Privacy-friendly proof of work</small>
        </div>
    </div>

    <script>
        const form = document.getElementById('challenge-form');
        const submitBtn = document.getElementById('submit-btn');
        const loading = document.getElementById('loading');
        const widget = document.querySelector('altcha-widget');

        // Show form when widget loads
        setTimeout(() => {{
            loading.style.display = 'none';
            form.style.display = 'block';
        }}, 1000);

        widget.addEventListener('statechange', (ev) => {{
            console.log('ALTCHA state:', ev.detail.state);

            switch(ev.detail.state) {{
                case 'verified':
                    submitBtn.disabled = false;
                    submitBtn.textContent = 'Continue to Site';
                    submitBtn.style.background = '#2e7d32';
                    break;
                case 'error':
                    submitBtn.disabled = true;
                    submitBtn.textContent = 'Verification Failed - Try Again';
                    setTimeout(() => widget.reset(), 2000);
                    break;
                case 'verifying':
                    submitBtn.disabled = true;
                    submitBtn.textContent = 'Verifying...';
                    break;
                case 'solving':
                    submitBtn.disabled = true;
                    submitBtn.textContent = 'Solving Challenge...';
                    break;
                default:
                    submitBtn.disabled = true;
                    submitBtn.textContent = 'Complete Verification';
                    submitBtn.style.background = '#e87722';
            }}
        }});

        form.addEventListener('submit', async (e) => {{
            e.preventDefault();

            // Get the payload from the form data or widget value
            const formData = new FormData(form);
            const payload = formData.get('altcha') || widget.value;

            if (!payload) {{
                alert('Please complete the verification first.');
                return;
            }}

            try {{
                const response = await fetch('/api/verify', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{altcha: payload}})
                }});

                if (response.ok) {{
                    window.location.href = '{}';
                }} else {{
                    alert('Verification failed. Please try again.');
                    widget.reset();
                    submitBtn.disabled = true;
                }}
            }} catch (error) {{
                alert('Error occurred. Please try again.');
                widget.reset();
                submitBtn.disabled = true;
            }}
        }});
    </script>
</body>
</html>
"#,
        host, return_to
    );

    Html(html)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let state = Arc::new(AppState {
        secret_key: SECRET_KEY.to_string(),
    });

    // Build the application with routes
    let app = Router::new()
        .route("/api/challenge", get(challenge_handler))
        .route("/api/verify", post(verify_handler))
        .route("/api/validate", get(validate_handler))
        .route("/", get(challenge_page_handler))
        .layer(
            ServiceBuilder::new().layer(
                CorsLayer::new()
                    .allow_origin(Any)
                    .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                    .allow_headers(Any)
                    .allow_credentials(false),
            ),
        )
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    info!("ALTCHA server starting on http://127.0.0.1:8080");
    info!("Serving domains: dataspace.princeton.edu, oar.princeton.edu");

    axum::serve(listener, app).await?;

    Ok(())
}
