#[test]
fn default_rootfs_path_is_under_data_dir() {
    let path = husker::default_rootfs_path();
    let data = husker::default_data_dir();
    assert!(
        path.starts_with(&data),
        "{} not under {}",
        path.display(),
        data.display()
    );
    assert!(
        path.ends_with("images/alpine-aarch64.ext4") || path.ends_with("images/alpine-x86_64.ext4")
    );
}

#[test]
fn default_images_base_url_is_resolvable_github_repo() {
    assert!(husker::DEFAULT_IMAGES_BASE_URL.contains("github.com"));
    assert!(husker::DEFAULT_IMAGES_BASE_URL.contains("rvben/husker"));
}
