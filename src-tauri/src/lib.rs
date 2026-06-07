mod commands;
mod crypto;
mod steam;

use std::sync::Mutex;
use std::time::Duration;

/// Shared application state managed by Tauri.
pub struct AppState {
    /// Base URL for the Steam Box API.
    pub api_base: String,
    /// Shared HTTP client with connection pooling and timeout.
    pub client: reqwest::Client,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Fix WebView2 data directory BEFORE anything else
    // Prevents "无法创建数据目录" error when running as admin
    if std::env::var("WEBVIEW2_USER_DATA_FOLDER").is_err() {
        let data_dir = dirs::data_local_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("SteamBox")
            .join("EBWebView");
        let _ = std::fs::create_dir_all(&data_dir);
        std::env::set_var("WEBVIEW2_USER_DATA_FOLDER", data_dir.to_string_lossy().to_string());
    }

    // Allow overriding the API base URL via environment variable
    let api_base = std::env::var("STEAMBOX_API")
        .unwrap_or_else(|_| "https://steam-box.fntiyqznzg.workers.dev".to_string());

    // Build a shared reqwest client
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .user_agent("SteamBox/1.0")
        .build()
        .expect("Failed to build HTTP client");

    let app_state = AppState {
        api_base,
        client,
    };

    // Cache for computed machine ID (computed once on first use)
    let machine_id_cache: Mutex<Option<String>> = Mutex::new(None);

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(app_state)
        .manage(machine_id_cache)
        .invoke_handler(tauri::generate_handler![
            commands::get_machine_code,
            commands::activate_cdk,
            commands::check_session,
            commands::unlock_all,
            commands::unlock_single,
            commands::repair,
            commands::wipe_game,
            commands::get_steam_path,
            commands::get_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
