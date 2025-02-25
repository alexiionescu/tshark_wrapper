#![allow(unused)]
use std::path::Path;

use regex::Regex;

pub(crate) fn get_path_suffix(path: &Path, delimiter: char) -> Option<&str> {
    let file_name = path.file_name()?.to_str()?;
    if let Some((_, suffix)) = file_name.rsplit_once(delimiter) {
        Some(suffix)
    } else {
        Some(file_name)
    }
}
pub(crate) fn get_path_match<'a>(path: &'a Path, format: &Regex) -> Option<&'a str> {
    let file_name = path.file_name()?.to_str()?;
    if let Some(m) = format.find(path.to_str()?) {
        Some(m.as_str())
    } else {
        Some(file_name)
    }
}
