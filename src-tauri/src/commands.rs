use crate::crypto;
use crate::steam;
use crate::AppState;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::State;

// ─── Response types ──────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ActivateResponse {
    pub success: bool,
    pub message: String,
    pub expiry: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SessionInfo {
    pub active: bool,
    pub expiry: Option<String>,
    pub cdk: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UnlockProgress {
    pub total: usize,
    pub written: usize,
    pub skipped: usize,
    pub errors: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SingleUnlockResponse {
    pub success: bool,
    pub name: Option<String>,
    pub message: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WipeResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RepairResponse {
    pub success: bool,
    pub message: String,
    pub files_written: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StatusInfo {
    pub activated: bool,
    pub expiry: Option<String>,
    pub game_count: usize,
    pub steam_path: Option<String>,
    pub depot_keys: usize,
}

// ─── API response types ──────────────────────────────────────────

#[derive(Deserialize, Debug)]
struct ApiRedeemResponse {
    success: Option<bool>,
    ok: Option<bool>,
    lua: Option<String>,
    lua_b64: Option<String>,
    expiry: Option<String>,
    name: Option<String>,
    appid: Option<String>,
    message: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct ApiAppidsPage {
    appids: Option<Vec<String>>,
    page: Option<u32>,
    total_pages: Option<u32>,
    total: Option<usize>,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct ApiPingResponse {
    depot_keys: Option<usize>,
    status: Option<String>,
}

#[derive(Deserialize, Debug)]
struct ApiRepairManifest {
    files: Option<Vec<RepairFile>>,
}

#[derive(Deserialize, Debug)]
struct RepairFile {
    name: String,
    url: Option<String>,
}

// ─── Session persistence ─────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct SessionData {
    cdk: String,
    expiry: String,
    activated_at: String,
}

fn session_dir() -> Option<PathBuf> {
    dirs::data_dir().map(|d| d.join("steam-box"))
}

fn session_file() -> Option<PathBuf> {
    session_dir().map(|d| d.join("session.dat"))
}

fn save_session(cdk: &str, expiry: &str, machine_id: &str) -> Result<(), String> {
    let dir = session_dir().ok_or("Cannot determine app data directory")?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    let data = SessionData {
        cdk: cdk.to_string(),
        expiry: expiry.to_string(),
        activated_at: chrono::Utc::now().to_rfc3339(),
    };

    let json = serde_json::to_string(&data).map_err(|e| e.to_string())?;
    let encrypted = crypto::encrypt(json.as_bytes(), machine_id).map_err(|e| e.to_string())?;

    let path = session_file().ok_or("Cannot determine session file path")?;
    fs::write(&path, &encrypted).map_err(|e| e.to_string())?;
    Ok(())
}

fn load_session(machine_id: &str) -> Result<SessionData, String> {
    let path = session_file().ok_or("Cannot determine session file path")?;
    if !path.exists() {
        return Err("No session file found".to_string());
    }

    let data = fs::read(&path).map_err(|e| e.to_string())?;
    let decrypted = crypto::decrypt(&data, machine_id).map_err(|e| e.to_string())?;
    let json_str = String::from_utf8(decrypted).map_err(|e| e.to_string())?;
    let session: SessionData = serde_json::from_str(&json_str).map_err(|e| e.to_string())?;
    Ok(session)
}

// ─── Machine ID ──────────────────────────────────────────────────

fn compute_machine_id_inner() -> Result<String, String> {
    // On Windows: try WMI for hardware serials, fall back to registry ComputerHardwareId
    #[cfg(windows)]
    {
        if let Ok(id) = get_machine_id_wmi() {
            return Ok(id);
        }
        if let Ok(id) = get_machine_id_registry() {
            return Ok(id);
        }
    }

    // Cross-platform fallback: use hostname + dirs combination
    let mut hasher = Sha256::new();

    if let Ok(hostname) = hostname::get() {
        hasher.update(hostname.to_string_lossy().as_bytes());
    }

    if let Some(home) = dirs::home_dir() {
        hasher.update(home.to_string_lossy().as_bytes());
    }

    // Add some system-specific salt
    if let Some(data_dir) = dirs::data_dir() {
        hasher.update(data_dir.to_string_lossy().as_bytes());
    }

    hasher.update(b"steam-box-salt-v1");

    let result = hasher.finalize();
    let hash = hex::encode(result);
    // Format as XXXX-XXXX-XXXX-XXXX (first 32 hex chars, grouped)
    Ok(format!(
        "{}-{}-{}-{}",
        &hash[0..8],
        &hash[8..16],
        &hash[16..24],
        &hash[24..32]
    ))
}

#[cfg(windows)]
fn get_machine_id_wmi() -> Result<String, String> {
    use std::collections::HashMap;
    use wmi::{COMLibrary, WMIConnection};

    let com = COMLibrary::new().map_err(|e| e.to_string())?;
    let wmi = WMIConnection::new(com).map_err(|e| e.to_string())?;

    let mut combined = String::new();

    // Get baseboard serial
    let boards: Vec<HashMap<String, wmi::Variant>> = wmi
        .raw_query("SELECT SerialNumber FROM Win32_BaseBoard")
        .map_err(|e| e.to_string())?;
    for board in &boards {
        if let Some(wmi::Variant::String(serial)) = board.get("SerialNumber") {
            combined.push_str(serial);
        }
    }

    // Get disk serial
    let disks: Vec<HashMap<String, wmi::Variant>> = wmi
        .raw_query("SELECT SerialNumber FROM Win32_DiskDrive WHERE MediaType LIKE '%Fixed%'")
        .map_err(|e| e.to_string())?;
    for disk in &disks {
        if let Some(wmi::Variant::String(serial)) = disk.get("SerialNumber") {
            combined.push_str(serial);
        }
    }

    if combined.is_empty() {
        return Err("No hardware serials found via WMI".to_string());
    }

    let mut hasher = Sha256::new();
    hasher.update(combined.as_bytes());
    let result = hasher.finalize();
    let hash = hex::encode(result);
    Ok(format!(
        "{}-{}-{}-{}",
        &hash[0..8],
        &hash[8..16],
        &hash[16..24],
        &hash[24..32]
    ))
}

#[cfg(windows)]
fn get_machine_id_registry() -> Result<String, String> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm
        .open_subkey("SYSTEM\\CurrentControlSet\\Control\\SystemInformation")
        .map_err(|e| e.to_string())?;
    let hw_id: String = key
        .get_value("ComputerHardwareId")
        .map_err(|e| e.to_string())?;

    let mut hasher = Sha256::new();
    hasher.update(hw_id.as_bytes());
    let result = hasher.finalize();
    let hash = hex::encode(result);
    Ok(format!(
        "{}-{}-{}-{}",
        &hash[0..8],
        &hash[8..16],
        &hash[16..24],
        &hash[24..32]
    ))
}

// ─── Tauri Commands ──────────────────────────────────────────────

/// Get the machine ID (computed once and cached).
#[tauri::command]
pub async fn get_machine_code(
    machine_id_cache: State<'_, Mutex<Option<String>>>,
) -> Result<String, String> {
    let mut cache = machine_id_cache.lock().map_err(|e| e.to_string())?;
    if let Some(ref id) = *cache {
        return Ok(id.clone());
    }

    let id = compute_machine_id_inner()?;
    *cache = Some(id.clone());
    Ok(id)
}

/// Activate a CDK license key.
#[tauri::command]
pub async fn activate_cdk(
    cdk: String,
    machine_code: String,
    state: State<'_, AppState>,
    machine_id_cache: State<'_, Mutex<Option<String>>>,
) -> Result<ActivateResponse, String> {
    if cdk.trim().is_empty() {
        return Ok(ActivateResponse {
            success: false,
            message: "CDK cannot be empty".to_string(),
            expiry: None,
        });
    }

    // Ensure we have a machine ID
    let machine_id = {
        let cache = machine_id_cache.lock().map_err(|e| e.to_string())?;
        cache
            .clone()
            .unwrap_or_else(|| machine_code.clone())
    };

    let body = serde_json::json!({
        "cdk": cdk.trim(),
        "machine": machine_id,
    });

    let url = format!("{}/api/redeem", state.api_base);
    let resp = state
        .client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Network error: {}", e))?;

    if !resp.status().is_success() {
        return Ok(ActivateResponse {
            success: false,
            message: format!("Server returned status {}", resp.status()),
            expiry: None,
        });
    }

    let api_resp: ApiRedeemResponse = resp.json().await.map_err(|e| format!("Parse error: {}", e))?;

    let is_success = api_resp.success.unwrap_or(false) || api_resp.ok.unwrap_or(false);

    if is_success {
        // Decode and write Lua payload if present
        if let Some(lua_b64) = api_resp.lua_b64.as_ref().or(api_resp.lua.as_ref()) {
            let lua_bytes = base64::engine::general_purpose::STANDARD
                .decode(lua_b64)
                .map_err(|e| format!("Base64 decode error: {}", e))?;
            let lua_content = String::from_utf8(lua_bytes)
                .map_err(|e| format!("UTF-8 error: {}", e))?;

            if let Ok(steam_path) = steam::detect_steam_path() {
                let _ = steam::write_lua(&steam_path, &cdk, &lua_content);
            }
        }

        // Save session
        let expiry = api_resp.expiry.clone().unwrap_or_else(|| "2026-12-31".to_string());
        let _ = save_session(&cdk, &expiry, &machine_id);

        Ok(ActivateResponse {
            success: true,
            message: "Activation successful".to_string(),
            expiry: Some(expiry),
        })
    } else {
        Ok(ActivateResponse {
            success: false,
            message: api_resp
                .message
                .or(api_resp.error)
                .unwrap_or_else(|| "Activation failed".to_string()),
            expiry: None,
        })
    }
}

/// Check if there is an existing valid session.
#[tauri::command]
pub async fn check_session(
    machine_id_cache: State<'_, Mutex<Option<String>>>,
) -> Result<SessionInfo, String> {
    let machine_id = {
        let mut cache = machine_id_cache.lock().map_err(|e| e.to_string())?;
        if cache.is_none() {
            let id = compute_machine_id_inner()?;
            *cache = Some(id);
        }
        cache.clone().unwrap()
    };

    match load_session(&machine_id) {
        Ok(session) => {
            // Check if session has expired
            let now = chrono::Utc::now();
            let is_active = if let Ok(expiry_date) =
                chrono::NaiveDate::parse_from_str(&session.expiry, "%Y-%m-%d")
            {
                let expiry_dt = expiry_date
                    .and_hms_opt(23, 59, 59)
                    .unwrap()
                    .and_utc();
                now < expiry_dt
            } else {
                // If we can't parse the date, assume active
                true
            };

            Ok(SessionInfo {
                active: is_active,
                expiry: Some(session.expiry),
                cdk: Some(session.cdk),
            })
        }
        Err(_) => Ok(SessionInfo {
            active: false,
            expiry: None,
            cdk: None,
        }),
    }
}

/// Unlock all games -- paginate through the API and write Lua files.
#[tauri::command]
pub async fn unlock_all(state: State<'_, AppState>) -> Result<UnlockProgress, String> {
    let steam_path = steam::detect_steam_path().map_err(|e| format!("Steam not found: {}", e))?;

    let mut all_appids: Vec<String> = Vec::new();
    let mut page = 1u32;
    let mut total_pages: u32;

    // Paginate through API to get all AppIDs
    loop {
        let url = format!("{}/api/universal/appids?page={}", state.api_base, page);
        let resp = state
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("Network error: {}", e))?;

        if !resp.status().is_success() {
            break;
        }

        let page_data: ApiAppidsPage =
            resp.json().await.map_err(|e| format!("Parse error: {}", e))?;

        if let Some(appids) = page_data.appids {
            if appids.is_empty() {
                break;
            }
            all_appids.extend(appids);
        } else {
            break;
        }

        total_pages = page_data.total_pages.unwrap_or(1);
        if page >= total_pages {
            break;
        }
        page += 1;
    }

    let total = all_appids.len();
    let mut written = 0usize;
    let mut skipped = 0usize;
    let mut errors: Vec<String> = Vec::new();

    // For each AppID, request the Lua payload and write it
    for appid in &all_appids {
        let cdk = format!("UNIVERSAL-{}", appid);
        let body = serde_json::json!({
            "cdk": cdk,
            "machine": "universal",
        });

        let url = format!("{}/api/redeem", state.api_base);
        match state.client.post(&url).json(&body).send().await {
            Ok(resp) => {
                if let Ok(api_resp) = resp.json::<ApiRedeemResponse>().await {
                    let is_success =
                        api_resp.success.unwrap_or(false) || api_resp.ok.unwrap_or(false);
                    if is_success {
                        if let Some(lua_b64) = api_resp.lua_b64.as_ref().or(api_resp.lua.as_ref()) {
                            match base64::engine::general_purpose::STANDARD.decode(lua_b64) {
                                Ok(lua_bytes) => match String::from_utf8(lua_bytes) {
                                    Ok(lua_content) => {
                                        match steam::write_lua(&steam_path, appid, &lua_content) {
                                            Ok(_) => written += 1,
                                            Err(e) => {
                                                errors.push(format!("{}: write error: {}", appid, e))
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        errors.push(format!("{}: UTF-8 error: {}", appid, e))
                                    }
                                },
                                Err(e) => {
                                    errors.push(format!("{}: base64 error: {}", appid, e))
                                }
                            }
                        } else {
                            skipped += 1;
                        }
                    } else {
                        skipped += 1;
                    }
                } else {
                    errors.push(format!("{}: response parse error", appid));
                }
            }
            Err(e) => {
                errors.push(format!("{}: network error: {}", appid, e));
            }
        }
    }

    Ok(UnlockProgress {
        total,
        written,
        skipped,
        errors,
    })
}

/// Unlock a single game by AppID.
#[tauri::command]
pub async fn unlock_single(
    appid: String,
    state: State<'_, AppState>,
) -> Result<SingleUnlockResponse, String> {
    if appid.trim().is_empty() {
        return Ok(SingleUnlockResponse {
            success: false,
            name: None,
            message: "AppID cannot be empty".to_string(),
        });
    }

    let steam_path = steam::detect_steam_path().map_err(|e| format!("Steam not found: {}", e))?;

    let cdk = format!("UNIVERSAL-{}", appid.trim());
    let body = serde_json::json!({
        "cdk": cdk,
        "machine": "universal",
    });

    let url = format!("{}/api/redeem", state.api_base);
    let resp = state
        .client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Network error: {}", e))?;

    if !resp.status().is_success() {
        return Ok(SingleUnlockResponse {
            success: false,
            name: None,
            message: format!("Server returned status {}", resp.status()),
        });
    }

    let api_resp: ApiRedeemResponse = resp.json().await.map_err(|e| format!("Parse error: {}", e))?;

    let is_success = api_resp.success.unwrap_or(false) || api_resp.ok.unwrap_or(false);

    if is_success {
        if let Some(lua_b64) = api_resp.lua_b64.as_ref().or(api_resp.lua.as_ref()) {
            let lua_bytes = base64::engine::general_purpose::STANDARD
                .decode(lua_b64)
                .map_err(|e| format!("Base64 decode error: {}", e))?;
            let lua_content =
                String::from_utf8(lua_bytes).map_err(|e| format!("UTF-8 error: {}", e))?;

            steam::write_lua(&steam_path, appid.trim(), &lua_content)
                .map_err(|e| format!("Write error: {}", e))?;
        }

        Ok(SingleUnlockResponse {
            success: true,
            name: api_resp.name.clone(),
            message: "Unlock successful".to_string(),
        })
    } else {
        Ok(SingleUnlockResponse {
            success: false,
            name: None,
            message: api_resp
                .message
                .or(api_resp.error)
                .unwrap_or_else(|| "Unlock failed".to_string()),
        })
    }
}

/// Repair -- download required DLLs and place them in the Steam directory.
#[tauri::command]
pub async fn repair(state: State<'_, AppState>) -> Result<RepairResponse, String> {
    let steam_path = steam::detect_steam_path().map_err(|e| format!("Steam not found: {}", e))?;

    // Fetch the repair manifest from the API
    let manifest_url = format!("{}/api/repair/manifest", state.api_base);
    let repair_files: Vec<RepairFile> = match state.client.get(&manifest_url).send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                match resp.json::<ApiRepairManifest>().await {
                    Ok(manifest) => manifest.files.unwrap_or_default(),
                    Err(_) => {
                        // Fallback: use a default repair file list
                        get_default_repair_files()
                    }
                }
            } else {
                get_default_repair_files()
            }
        }
        Err(_) => get_default_repair_files(),
    };

    let mut files_written = 0usize;
    for file in &repair_files {
        let download_url = file.url.clone().unwrap_or_else(|| {
            format!("{}/dl/{}", state.api_base, file.name)
        });

        match state.client.get(&download_url).send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    match resp.bytes().await {
                        Ok(bytes) => {
                            let dest = steam_path.join(&file.name);
                            if let Err(e) = fs::write(&dest, &bytes) {
                                eprintln!("Failed to write {}: {}", file.name, e);
                            } else {
                                files_written += 1;
                            }
                        }
                        Err(e) => eprintln!("Failed to read bytes for {}: {}", file.name, e),
                    }
                }
            }
            Err(e) => eprintln!("Failed to download {}: {}", file.name, e),
        }
    }

    Ok(RepairResponse {
        success: files_written > 0,
        message: format!("Repaired {} files", files_written),
        files_written,
    })
}

fn get_default_repair_files() -> Vec<RepairFile> {
    vec![
        RepairFile {
            name: "steam_api.dll".to_string(),
            url: None,
        },
        RepairFile {
            name: "steam_api64.dll".to_string(),
            url: None,
        },
    ]
}

/// Wipe (delete) the Lua file for a specific game.
#[tauri::command]
pub async fn wipe_game(appid: String) -> Result<WipeResponse, String> {
    if appid.trim().is_empty() {
        return Ok(WipeResponse {
            success: false,
            message: "AppID cannot be empty".to_string(),
        });
    }

    let steam_path = steam::detect_steam_path().map_err(|e| format!("Steam not found: {}", e))?;

    match steam::remove_lua(&steam_path, appid.trim()) {
        Ok(true) => Ok(WipeResponse {
            success: true,
            message: format!("Game {} wiped successfully", appid),
        }),
        Ok(false) => Ok(WipeResponse {
            success: false,
            message: format!("Game {} not found in local files", appid),
        }),
        Err(e) => Ok(WipeResponse {
            success: false,
            message: format!("Wipe failed: {}", e),
        }),
    }
}

/// Get the detected Steam installation path.
#[tauri::command]
pub async fn get_steam_path() -> Result<String, String> {
    let path = steam::detect_steam_path().map_err(|e| format!("Steam not found: {}", e))?;
    Ok(path.to_string_lossy().to_string())
}

/// Get composite status information.
#[tauri::command]
pub async fn get_status(
    state: State<'_, AppState>,
    machine_id_cache: State<'_, Mutex<Option<String>>>,
) -> Result<StatusInfo, String> {
    // Check session
    let (activated, expiry) = {
        let machine_id = {
            let cache = machine_id_cache.lock().map_err(|e| e.to_string())?;
            cache.clone()
        };

        if let Some(ref mid) = machine_id {
            match load_session(mid) {
                Ok(session) => {
                    let now = chrono::Utc::now();
                    let is_active =
                        if let Ok(d) = chrono::NaiveDate::parse_from_str(&session.expiry, "%Y-%m-%d") {
                            let expiry_dt = d.and_hms_opt(23, 59, 59).unwrap().and_utc();
                            now < expiry_dt
                        } else {
                            true
                        };
                    (is_active, Some(session.expiry))
                }
                Err(_) => (false, None),
            }
        } else {
            (false, None)
        }
    };

    // Get game count
    let (count, steam_path_str) = match steam::detect_steam_path() {
        Ok(sp) => {
            let c = steam::game_count(&sp).unwrap_or(0);
            let s = sp.to_string_lossy().to_string();
            (c, Some(s))
        }
        Err(_) => (0, None),
    };

    // Ping API for depot_keys count
    let depot_keys = {
        let url = format!("{}/api/ping", state.api_base);
        match state.client.get(&url).send().await {
            Ok(resp) => match resp.json::<ApiPingResponse>().await {
                Ok(ping) => ping.depot_keys.unwrap_or(0),
                Err(_) => 0,
            },
            Err(_) => 0,
        }
    };

    Ok(StatusInfo {
        activated,
        expiry,
        game_count: count,
        steam_path: steam_path_str,
        depot_keys,
    })
}

// ─── Window control ─────────────────────────────────────────────

#[tauri::command]
pub async fn minimize_window(window: tauri::Window) -> Result<(), String> {
    window.minimize().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn close_window(window: tauri::Window) -> Result<(), String> {
    window.close().map_err(|e| e.to_string())
}
