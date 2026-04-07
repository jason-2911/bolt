//! Client directory transfer: recursive upload and download using proper protocol.

use std::path::Path;

use anyhow::Context as _;
use walkdir::WalkDir;

use crate::client::Session;
use crate::transfer::{download_opts, list_dir, upload_opts};

// ── Upload Dir ────────────────────────────────────────────────────────────

/// Recursively upload `local_dir` to `remote_dst` on the server.
pub async fn upload_dir(
    session: &Session,
    local_dir: &Path,
    remote_dst: &str,
) -> anyhow::Result<()> {
    upload_dir_opts(session, local_dir, remote_dst, false).await
}

pub async fn upload_dir_opts(
    session: &Session,
    local_dir: &Path,
    remote_dst: &str,
    preserve: bool,
) -> anyhow::Result<()> {
    let files: Vec<std::path::PathBuf> = WalkDir::new(local_dir)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect();

    if files.is_empty() {
        eprintln!("bolt: {} is empty", local_dir.display());
        return Ok(());
    }

    eprintln!(
        "bolt: uploading {} file(s) from {} -> {}",
        files.len(),
        local_dir.display(),
        remote_dst
    );

    let total = files.len();
    for (i, local_path) in files.iter().enumerate() {
        let rel = local_path.strip_prefix(local_dir).unwrap_or(local_path);
        let remote_path = format!("{}/{}", remote_dst.trim_end_matches('/'), rel.display());
        eprint!("[{}/{}] ", i + 1, total);
        upload_opts(session, local_path, &remote_path, preserve)
            .await
            .with_context(|| format!("upload {}", rel.display()))?;
    }

    eprintln!("bolt: upload complete — {} file(s)", total);
    Ok(())
}

// ── Download Dir ──────────────────────────────────────────────────────────

/// Recursively download `remote_dir` from the server to `local_dst`.
/// Uses the DirList protocol — no exec+find needed.
pub async fn download_dir(
    session: &Session,
    remote_dir: &str,
    local_dst: &Path,
) -> anyhow::Result<()> {
    download_dir_opts(session, remote_dir, local_dst, false).await
}

pub async fn download_dir_opts(
    session: &Session,
    remote_dir: &str,
    local_dst: &Path,
    preserve: bool,
) -> anyhow::Result<()> {
    // Recursively list all files from the server
    let remote_dir = remote_dir.trim_end_matches('/');
    let file_paths = list_all_files(session, remote_dir).await?;

    if file_paths.is_empty() {
        eprintln!("bolt: {remote_dir} is empty or does not exist");
        return Ok(());
    }

    eprintln!(
        "bolt: downloading {} file(s) from :{} -> {}",
        file_paths.len(),
        remote_dir,
        local_dst.display()
    );

    let total = file_paths.len();
    for (i, remote_path) in file_paths.iter().enumerate() {
        let rel = remote_path
            .strip_prefix(remote_dir)
            .unwrap_or(remote_path.as_str())
            .trim_start_matches('/');
        let local_path = local_dst.join(rel);

        if let Some(parent) = local_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("mkdir {}", parent.display()))?;
        }

        eprint!("[{}/{}] ", i + 1, total);
        download_opts(session, remote_path, &local_path, preserve)
            .await
            .with_context(|| format!("download {rel}"))?;
    }

    eprintln!("bolt: download complete — {} file(s)", total);
    Ok(())
}

/// Recursively list all files under `remote_dir` using the DirList protocol.
async fn list_all_files(session: &Session, remote_dir: &str) -> anyhow::Result<Vec<String>> {
    let mut result = Vec::new();
    list_recursive(session, remote_dir, &mut result).await?;
    result.sort();
    Ok(result)
}

fn list_recursive<'a>(
    session: &'a Session,
    path: &'a str,
    result: &'a mut Vec<String>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>> {
    Box::pin(async move {
        let entries = list_dir(session, path).await?;
        for entry in entries {
            let full = format!("{}/{}", path.trim_end_matches('/'), entry.name);
            if entry.is_dir {
                list_recursive(session, &full, result).await?;
            } else {
                result.push(full);
            }
        }
        Ok(())
    })
}
