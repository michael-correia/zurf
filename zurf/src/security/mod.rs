//pub mod s0;
pub mod s2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key(pub [u8; 16]);

impl Key {
    pub fn new(key: [u8; 16]) -> Self {
        Key(key)
    }
}
