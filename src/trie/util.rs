pub(crate) fn has_prefix(s: &[u8], prefix: &[u8]) -> bool {
    s.starts_with(prefix)
}

pub(crate) fn assert_subset(sub: u16, sup: u16) {
    assert_eq!(sub & sup, sub);
}
