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
                    ni = 0;
                }
            } else {
                ni = 0;
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
        assert_eq!(
            t,
            [
                10, 20, 21, 22, 30, 50, 51, 80, 81, 90, 91, 10, 20, 21, 22, 30, 50, 51, 80, 81, 90,
                91
            ]
        );
    }

    #[test]
    fn test_replace_data() {
        let t = "023130320d0a000000313032030405060708090a0b0c0d0e0f14151A1B7F20313032";
        let a = hex::decode(t).expect("decode hex ok");
        println!("{:?}", a);
        let a = a
            .maybe_replace_buf(b"\r", b"<CR>")
            .maybe_replace_buf(b"\t", b"<TAB>")
            .maybe_replace_buf(b"\x00", b"<NUL>")
            .maybe_replace_buf(b"\x02", b"<STX>")
            .maybe_replace_buf(b"\x03", b"<ETX>")
            .maybe_replace_buf(b"\x04", b"<EOT>")
            .maybe_replace_buf(b"\n", b"<LF>");
        let a = String::from_utf8(a).expect("decode utf8 ok");
        assert_eq!(
            a,
            "<STX>102<CR><LF><NUL><NUL><NUL>102<ETX><EOT>\u{5}\u{6}\u{7}\u{8}<TAB><LF>\u{b}\u{c}<CR>\u{e}\u{f}\u{14}\u{15}\u{1a}\u{1b}\u{7f} 102"
        );
    }
}
