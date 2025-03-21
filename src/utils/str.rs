use std::borrow::Cow;

use itertools::Itertools as _;

pub trait MaybeReplaceVecExt<T>
where
    T: std::cmp::PartialEq + std::clone::Clone,
{
    fn maybe_replace_buf(self, needle: &[T], replacement: &[T]) -> Vec<T>;
}

impl<T> MaybeReplaceVecExt<T> for Vec<T>
where
    T: std::cmp::PartialEq + std::clone::Clone,
{
    fn maybe_replace_buf(mut self, needle: &[T], replacement: &[T]) -> Vec<T> {
        if needle.is_empty() {
            return self;
        }
        let mut ni = 0;
        let mut i = 0;
        while i < self.len() {
            if self[i + ni] == needle[ni] {
                ni += 1;
                if ni == needle.len() {
                    self.splice(i..(i + ni), replacement.iter().cloned());
                    i += replacement.len();
                }
            } else {
                i += 1;
            }
        }
        self
    }
}
pub trait MaybeReplaceExt<'a> {
    fn maybe_replace(self, needle: &str, replacement: &str) -> Cow<'a, str>;
    fn maybe_replace_closure<F>(self, needle: &str, replacement: F) -> Cow<'a, str>
    where
        F: FnOnce() -> String;
}

impl<'a> MaybeReplaceExt<'a> for &'a str {
    fn maybe_replace(self, needle: &str, replacement: &str) -> Cow<'a, str> {
        // Assumes that searching twice is better than unconditionally allocating
        if self.contains(needle) {
            self.replace(needle, replacement).into()
        } else {
            self.into()
        }
    }

    fn maybe_replace_closure<F>(self, needle: &str, replacement: F) -> Cow<'a, str>
    where
        F: FnOnce() -> String,
    {
        if self.contains(needle) {
            self.replace(needle, &replacement()).into()
        } else {
            self.into()
        }
    }
}

impl<'a> MaybeReplaceExt<'a> for Cow<'a, str> {
    fn maybe_replace(self, needle: &str, replacement: &str) -> Cow<'a, str> {
        // Assumes that searching twice is better than unconditionally allocating
        if self.contains(needle) {
            self.replace(needle, replacement).into()
        } else {
            self
        }
    }

    fn maybe_replace_closure<F>(self, needle: &str, replacement: F) -> Cow<'a, str>
    where
        F: FnOnce() -> String,
    {
        if self.contains(needle) {
            self.replace(needle, &replacement()).into()
        } else {
            self
        }
    }
}

// MARK: TESTS
#[cfg(test)]
mod test {
    use super::MaybeReplaceVecExt as _;
    #[test]
    fn test_replace_buf() {
        let t = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let t = t
            .maybe_replace_buf(&[1], &[10])
            .maybe_replace_buf(&[2], &[20, 21, 22])
            .maybe_replace_buf(&[3, 4], &[30])
            .maybe_replace_buf(&[5, 6, 7], &[50, 51])
            .maybe_replace_buf(&[8, 9], &[80, 81, 90, 91]);
        println!("{:?}", &t);
    }
}
