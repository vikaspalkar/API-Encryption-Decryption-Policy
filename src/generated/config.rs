use serde::Deserialize;
#[derive(Deserialize, Clone, Debug)]
pub struct CacheConfigConfig {
    #[serde(alias = "ttl")]
    pub ttl: i64,
}
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(alias = "SuccessStatusCode")]
    pub success_status_code: Option<String>,
    #[serde(alias = "SuccessStatusCodeDecrypt")]
    pub success_status_code_decrypt: Option<String>,
    #[serde(alias = "awsAccessKey")]
    pub aws_access_key: String,
    #[serde(alias = "awsAccessSecret")]
    pub aws_access_secret: String,
    #[serde(alias = "awsRegion")]
    pub aws_region: String,
    #[serde(alias = "awsService", deserialize_with = "pdk::serde::deserialize_service")]
    pub aws_service: pdk::hl::Service,
    #[serde(alias = "cacheConfig")]
    pub cache_config: CacheConfigConfig,
    #[serde(alias = "requestMode")]
    pub request_mode: String,
    #[serde(alias = "responseMode")]
    pub response_mode: String,
}
#[pdk::hl::entrypoint_flex]
fn init(abi: &dyn pdk::flex_abi::api::FlexAbi) -> Result<(), anyhow::Error> {
    let config: Config = serde_json::from_slice(abi.get_configuration())
        .map_err(|err| {
            anyhow::anyhow!(
                "Failed to parse configuration '{}'. Cause: {}",
                String::from_utf8_lossy(abi.get_configuration()), err
            )
        })?;
    abi.service_create(config.aws_service)?;
    abi.setup()?;
    Ok(())
}
