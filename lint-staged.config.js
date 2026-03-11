export default {
  "*.rs": () => ["cargo fmt --all -- --check", "cargo clippy --workspace -- -D warnings"],
};
