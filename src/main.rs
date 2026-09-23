#[tokio::main]
async fn main() {
    std::process::exit(ms_entra_cli::cli::execute().await);
}
