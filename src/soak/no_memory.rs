//! Krok 10 (A3): produkční kód si nepamatuje seedy, sítě ani adresy z měření.
//!
//! Test prochází zdrojové soubory (bez testovacích modulů a bez komentářů) a hledá
//! seedy ladicích i držených sad a adresy, které generátor používá jako pevné
//! výchozí hodnoty scénářů. Jakýkoli nález znamená, že by se chování dalo „naučit“
//! na konkrétní měření, a test selže.

use std::path::{Path, PathBuf};

/// Seedy ladicích a držených sad kroků 7 až 10 (impl-krok9.md B1, impl-krok10.md C).
const SEEDS: &[&str] = &[
    "20261102", "20261103", "20261104", "20261110", "20262201", "20262202", "20262301",
    "20262302", "20262401", "20262402", "20261901", "20262001", "20262101", "20262102",
    "20261201", "20261301",
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Produkční část souboru: bez prvního `#[cfg(test)]` dál a bez řádků komentářů.
fn production_text(source: &str) -> String {
    let cut = source.find("#[cfg(test)]").unwrap_or(source.len());
    source[..cut]
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn production_code_remembers_no_measurement_seed() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    assert!(files.len() > 50, "zdrojove soubory nenalezeny");
    let mut found = Vec::new();
    for file in files {
        if file.file_name().is_some_and(|n| n == "no_memory.rs") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        let body = production_text(&text);
        for seed in SEEDS {
            if body.contains(seed) {
                found.push(format!("{}: {seed}", file.display()));
            }
        }
    }
    assert!(found.is_empty(), "pevne seedy v produkcnim kodu: {found:?}");
}
