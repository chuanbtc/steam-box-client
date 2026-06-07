use std::fs;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SteamError {
    #[error("Steam installation not found")]
    NotFound,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[allow(dead_code)]
    #[error("Registry error: {0}")]
    Registry(String),
}

/// Detect the Steam installation path.
///
/// On Windows, checks the registry first (HKCU and HKLM), then falls back to
/// common filesystem paths. On non-Windows platforms, checks common Linux/macOS paths.
pub fn detect_steam_path() -> Result<PathBuf, SteamError> {
    // Try registry on Windows
    #[cfg(windows)]
    {
        if let Some(path) = try_registry_steam_path() {
            let p = PathBuf::from(&path);
            if p.exists() {
                return Ok(p);
            }
        }
    }

    // Filesystem fallbacks
    let candidates = get_filesystem_candidates();
    for candidate in &candidates {
        let p = PathBuf::from(candidate);
        if p.exists() && p.join("steam.exe").exists() || p.join("Steam.exe").exists() {
            return Ok(p);
        }
        // Also accept if directory exists and has steamapps
        if p.exists() && p.join("steamapps").exists() {
            return Ok(p);
        }
    }

    // Last resort: just check if the directory exists
    for candidate in &candidates {
        let p = PathBuf::from(candidate);
        if p.exists() {
            return Ok(p);
        }
    }

    Err(SteamError::NotFound)
}

#[cfg(windows)]
fn try_registry_steam_path() -> Option<String> {
    use winreg::enums::*;
    use winreg::RegKey;

    // Try HKCU first
    if let Ok(hkcu) = RegKey::predef(HKEY_CURRENT_USER).open_subkey("SOFTWARE\\Valve\\Steam") {
        if let Ok(path) = hkcu.get_value::<String, _>("SteamPath") {
            return Some(path);
        }
        if let Ok(path) = hkcu.get_value::<String, _>("InstallPath") {
            return Some(path);
        }
    }

    // Try HKLM
    if let Ok(hklm) =
        RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey("SOFTWARE\\Valve\\Steam")
    {
        if let Ok(path) = hklm.get_value::<String, _>("InstallPath") {
            return Some(path);
        }
    }

    // Try HKLM WOW64 node
    if let Ok(hklm) = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey("SOFTWARE\\WOW6432Node\\Valve\\Steam")
    {
        if let Ok(path) = hklm.get_value::<String, _>("InstallPath") {
            return Some(path);
        }
    }

    None
}

#[cfg(not(windows))]
fn get_filesystem_candidates() -> Vec<String> {
    let mut candidates = Vec::new();
    if let Some(home) = dirs::home_dir() {
        candidates.push(
            home.join(".steam/steam")
                .to_string_lossy()
                .to_string(),
        );
        candidates.push(
            home.join(".local/share/Steam")
                .to_string_lossy()
                .to_string(),
        );
        // macOS
        candidates.push(
            home.join("Library/Application Support/Steam")
                .to_string_lossy()
                .to_string(),
        );
    }
    candidates
}

#[cfg(windows)]
fn get_filesystem_candidates() -> Vec<String> {
    vec![
        r"C:\Program Files (x86)\Steam".to_string(),
        r"C:\Program Files\Steam".to_string(),
        r"D:\Steam".to_string(),
        r"D:\Program Files (x86)\Steam".to_string(),
        r"E:\Steam".to_string(),
    ]
}

/// Get the path to the Lua plugin configuration directory.
/// This is `<steam_path>/config/stplug-in/`.
pub fn get_lua_dir(steam_path: &PathBuf) -> PathBuf {
    steam_path.join("config").join("stplug-in")
}

/// Ensure the Lua plugin directory exists, creating it if necessary.
pub fn ensure_lua_dir(steam_path: &PathBuf) -> Result<PathBuf, SteamError> {
    let lua_dir = get_lua_dir(steam_path);
    if !lua_dir.exists() {
        fs::create_dir_all(&lua_dir)?;
    }
    Ok(lua_dir)
}

/// Write a Lua file for a specific game AppID.
/// File is named `game_{appid}.lua` in the stplug-in directory.
pub fn write_lua(steam_path: &PathBuf, appid: &str, content: &str) -> Result<PathBuf, SteamError> {
    let lua_dir = ensure_lua_dir(steam_path)?;
    let filename = format!("game_{}.lua", appid);
    let filepath = lua_dir.join(&filename);
    fs::write(&filepath, content)?;
    Ok(filepath)
}

/// Remove the Lua file for a specific game AppID.
/// Returns Ok(true) if the file was deleted, Ok(false) if it didn't exist.
pub fn remove_lua(steam_path: &PathBuf, appid: &str) -> Result<bool, SteamError> {
    let lua_dir = get_lua_dir(steam_path);
    let filename = format!("game_{}.lua", appid);
    let filepath = lua_dir.join(&filename);
    if filepath.exists() {
        fs::remove_file(&filepath)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// List all game AppIDs that have Lua files in the stplug-in directory.
pub fn list_lua_games(steam_path: &PathBuf) -> Result<Vec<String>, SteamError> {
    let lua_dir = get_lua_dir(steam_path);
    if !lua_dir.exists() {
        return Ok(Vec::new());
    }

    let mut appids = Vec::new();
    for entry in fs::read_dir(&lua_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with("game_") && name.ends_with(".lua") {
            let appid = name
                .strip_prefix("game_")
                .unwrap()
                .strip_suffix(".lua")
                .unwrap()
                .to_string();
            appids.push(appid);
        }
    }
    Ok(appids)
}

/// Count the number of Lua game files in the stplug-in directory.
pub fn game_count(steam_path: &PathBuf) -> Result<usize, SteamError> {
    Ok(list_lua_games(steam_path)?.len())
}
