use acci_core::error::Error;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let password = "whiskey123!";
    let hash = acci_tests::helpers::auth::hash_password(password)?;
    println!("Password hash for '{}': {}", password, hash);
    Ok(())
}
